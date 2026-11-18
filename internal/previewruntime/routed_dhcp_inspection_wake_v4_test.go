package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type dhcpInspectionJobsV4 struct {
	dhcpRecoveryJobsV4
	verifyFailure bool
	verifies      atomic.Int32
}

func (j *dhcpInspectionJobsV4) Dispatch(ctx context.Context, command firewallipc.RoutedCommandV3) (any, error) {
	if command.Verb == "dhcp_verify" {
		j.verifies.Add(1)
		if j.verifyFailure {
			return nil, configpoc.ErrRecovery
		}
	}
	return j.dhcpRecoveryJobsV4.Dispatch(ctx, command)
}

// The session, codec, controller and both autonomous schedulers are real. Only
// selected persistence, physical L3 and full-store preflight are explicit doubles.
func TestRoutedDHCPInspectionWakeV4AutonomousRecovery(t *testing.T) {
	for _, mode := range []string{"complete", "verify-failure", "store-failure", "audit-failure", "full-inspection-failure", "stale-epoch", "stale-hash", "changed-owner", "changed-tuple", "disabled-wake", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, k, reader, fact := dhcpRuntimeFixtureV3(t)
				ctx := context.Background()
				if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
					t.Fatal(err)
				}
				s, selected, _ := integritySessionFixtureV3(t)
				observed := &dhcpRecoveryObservedV4{RoutedAuthorityV1: s.authority, r: r}
				jobs := &dhcpInspectionJobsV4{dhcpRecoveryJobsV4: dhcpRecoveryJobsV4{r}, verifyFailure: mode == "verify-failure"}
				s.authority, s.dhcpJobs = observed, jobs
				writer := &dhcpRecoveryWriterV4{r: r, k: k, reader: reader}
				controller := dhcpRecoveryControllerSessionV4(t, r, writer, s)
				defer controller.closeSchedulerV4()
				remote, err := NewRoutedRemoteIntegrityV3(controller.remote.client)
				if err != nil {
					t.Fatal(err)
				}
				if err = remote.Attach(ctx, selected.ref); err != nil {
					t.Fatal(err)
				}
				if result, e := remote.Inspect(ctx, selected.ref); e != nil || result.State != configpoc.IntegrityCompleteV1 {
					t.Fatal("initial complete inspection", result, e)
				}
				r.ready = func() error {
					s.integrity.mu.Lock()
					defer s.integrity.mu.Unlock()
					if s.integrity.blockedLocked() || s.integrity.phase != routedIntegrityReadyV3 {
						return configpoc.ErrRecovery
					}
					return nil
				}
				r.refreshReady = func() bool {
					s.integrity.mu.Lock()
					defer s.integrity.mu.Unlock()
					return !s.integrity.blockedLocked() && s.integrity.lastComplete != (configpoc.SelectionReferenceV2{}) && (s.integrity.phase == routedIntegrityReadyV3 || s.integrity.phase == routedIntegrityReconcilingV3)
				}
				grant, err := r.begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				work := &dhcpRuntimeWorkV3{grant: grant, phase: "prepared", hash: strings.Repeat("c", 64)}
				reader.work = work
				if err = r.apply(ctx, work.hash); err != nil {
					t.Fatal(err)
				}
				work.phase = "applied"
				if err = r.open(ctx, work.hash); err != nil {
					t.Fatal(err)
				}
				controller.work, controller.grant = r.work, r.grant
				var calls, proofs atomic.Int32
				service := &integrityWakeServiceV4{publications: make(chan struct{}, 1)}
				service.inspect = func(call context.Context) error {
					n := calls.Add(1)
					// A failing preflight must revoke even while the helper is Ready.
					if n == 1 || mode == "store-failure" {
						return configpoc.ErrStorage
					}
					if mode == "audit-failure" {
						return ErrUnavailable
					}
					result, e := remote.Inspect(call, selected.ref)
					if e == nil && result.State != configpoc.IntegrityCompleteV1 {
						e = configpoc.ErrRecovery
					}
					return e
				}
				service.publications <- struct{}{}
				scheduler := controller.startIntegritySchedulerV4(service)
				defer scheduler.Close()
				synctest.Wait()
				if calls.Load() != 1 {
					t.Fatal("initial preflight did not fail exactly once", calls.Load())
				}
				// The first scheduled attempt may lose TryLock to inspection.
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				controller.mu.Lock()
				r.mu.Lock()
				if mode == "full-inspection-failure" {
					selected.errorFull = configpoc.ErrStorage
				}
				next := configpoc.RoutedDHCPGrantV3{Epoch: grant.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, grant.Snapshot)}
				*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
				k.snapshot, observed.required = next.Snapshot, next.Snapshot.Hash
				switch mode {
				case "stale-epoch":
					fact.Epoch = grant.Epoch
				case "stale-hash":
					k.snapshot.Hash = strings.Repeat("f", 64)
				case "changed-owner":
					fact.Fact.Owner.Incarnation = strings.Repeat("e", 32)
				case "changed-tuple":
					fact.Fact.Address = "198.19.0.9/24"
				case "disabled-wake":
					controller.inspectionWake = nil
				}
				r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
					if k.forward || k.gate || r.opened || !k.target {
						return configpoc.ErrRecovery
					}
					proofs.Add(1)
					return nil
				}}
				r.mu.Unlock()
				controller.mu.Unlock()
				if mode == "shutdown" {
					scheduler.Close()
					controller.closeSchedulerV4()
				}
				// Advance the existing real DHCP timer, never inject an integrity tick.
				time.Sleep(1500 * time.Millisecond)
				synctest.Wait()
				if mode == "complete" {
					controller.mu.Lock()
					r.mu.Lock()
					opened := r.opened && k.gate && k.forward && !controller.recoveryOnly && reflect.DeepEqual(controller.grant, next)
					r.mu.Unlock()
					controller.mu.Unlock()
					if !opened || calls.Load() != 2 || proofs.Load() != 1 || jobs.verifies.Load() != 1 {
						t.Fatal("no autonomous complete inspection/open", opened, calls.Load(), proofs.Load(), jobs.verifies.Load())
					}
				} else {
					// Bounded ordinary publication and reconciliation storms may not
					// create additional proof wakes for an already consumed grant.
					for range 30 {
						select {
						case service.publications <- struct{}{}:
						default:
						}
						synctest.Wait()
					}
					time.Sleep(500 * time.Millisecond)
					synctest.Wait()
					controller.mu.Lock()
					r.mu.Lock()
					closed := !r.opened && !k.gate && !k.forward && k.target && controller.recoveryOnly && reflect.DeepEqual(controller.grant, grant)
					r.mu.Unlock()
					controller.mu.Unlock()
					want := int32(1)
					if mode == "store-failure" || mode == "audit-failure" || mode == "full-inspection-failure" {
						want = 2
					}
					if !closed || calls.Load() != want {
						t.Fatal("failed proof/inspection opened or looped", closed, calls.Load(), want)
					}
				}
				if controller.work != work.hash || writer.prepared != 0 || writer.archived != 0 || !reflect.DeepEqual(work.grant, grant) {
					t.Fatal("recovery changed selected Work")
				}
			})
		})
	}
}

func TestRoutedDHCPInspectionWakeV4RejectsUnverifiedGrants(t *testing.T) {
	// Invalid grant correlations must never reach the authenticated codec or
	// queue inspection. The same grant can only be consumed once per Work.
	r, k, reader, _ := dhcpRuntimeFixtureV3(t)
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	c := dhcpRecoveryControllerV4(t, r, &dhcpRecoveryWriterV4{r: r, k: k, reader: reader})
	c.recoveryOnly = true
	c.work = strings.Repeat("c", 64)
	c.grant = configpoc.RoutedDHCPGrantV3{Epoch: 1, Snapshot: dhcpRuntimeSnapshotV3(t)}
	wakes := 0
	c.inspectionWake = func() bool { wakes++; return true }
	next := configpoc.RoutedDHCPGrantV3{Epoch: 2, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, c.grant.Snapshot)}
	for _, mode := range []string{"epoch", "hash", "owner", "tuple", "canceled", "consumed"} {
		got := next
		ctx := context.Background()
		switch mode {
		case "epoch":
			got.Epoch = c.grant.Epoch
		case "hash":
			got.Snapshot.Hash = strings.Repeat("f", 64)
		case "owner":
			got.Snapshot.OwnerIncarnation = strings.Repeat("e", 32)
		case "tuple":
			got.Snapshot.Address = "198.19.0.9/24"
		case "canceled":
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		case "consumed":
			c.inspectionWork, c.inspectionGrant = c.work, next
		}
		if err := c.wakeClosedInspectionV4(ctx, got); !errors.Is(err, configpoc.ErrRecovery) || wakes != 0 {
			t.Fatal("unverified grant queued inspection", mode, err, wakes)
		}
	}
}
