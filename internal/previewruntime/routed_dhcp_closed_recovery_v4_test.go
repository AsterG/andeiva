package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// The selected writer/kernel are explicit doubles; the private session, codec
// and controller are real. Native selected-store recovery is qualified separately.
type dhcpRecoveryWriterV4 struct {
	r                  *RoutedDHCPRuntimeV3
	k                  *dhcpRuntimeKernelV3
	reader             *dhcpRuntimeReaderV3
	prepared, archived int
}

func (w *dhcpRecoveryWriterV4) Prepare(ctx context.Context) (string, error) {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if ctx.Err() != nil || w.reader.work != nil || w.r.work != "" || w.k.target {
		return "", configpoc.ErrRecovery
	}
	w.prepared++
	hash := strings.Repeat("d", 64)
	w.reader.work = &dhcpRuntimeWorkV3{grant: w.r.grant, phase: "prepared", hash: hash, generation: 2}
	return hash, nil
}

func (w *dhcpRecoveryWriterV4) Applied(ctx context.Context, work string) error {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if ctx.Err() != nil || w.reader.work == nil || w.reader.work.hash != work || !w.k.target || w.k.forward || w.k.gate {
		return configpoc.ErrRecovery
	}
	w.reader.work.phase = "applied"
	return nil
}

func (w *dhcpRecoveryWriterV4) Withdrawn(ctx context.Context, work string) error {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if ctx.Err() != nil || w.reader.work == nil || w.reader.work.hash != work || !w.r.withdrawn || w.k.target || w.k.forward || w.k.gate {
		return configpoc.ErrRecovery
	}
	s := w.reader.work.grant.Snapshot
	w.reader.last, w.reader.work = &s, nil
	w.archived++
	return nil
}

func dhcpRecoveryControllerV4(t *testing.T, r *RoutedDHCPRuntimeV3, writer *dhcpRecoveryWriterV4) *RoutedDHCPControllerV3 {
	t.Helper()
	s, err := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	s.integrity = &routedIntegrityGateV3{}
	return dhcpRecoveryControllerSessionV4(t, r, writer, s)
}

func dhcpRecoveryControllerSessionV4(t *testing.T, r *RoutedDHCPRuntimeV3, writer *dhcpRecoveryWriterV4, s *RoutedSessionV3) *RoutedDHCPControllerV3 {
	t.Helper()
	if s.dhcpJobs == nil {
		s.dhcp = r
	}
	s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
		return networkinventory.Snapshot{}, ErrUnavailable
	}
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(ctx, b, r.identity.RunID) }()
	client, err := firewallipc.ConnectRoutedDHCPRenewalV4(ctx, a, r.identity.RunID, r.identity.Namespace, false, false)
	if err != nil {
		cancel()
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); cancel(); <-done })
	return &RoutedDHCPControllerV3{remote: &routedDHCPRemoteV3{client: client}, writer: writer, work: r.work, grant: r.grant}
}

type dhcpRecoveryJobsV4 struct{ r *RoutedDHCPRuntimeV3 }

func (j dhcpRecoveryJobsV4) SameEffectiveRenewalV4() bool { return j.r.SameEffectiveRenewalV4() }
func (j dhcpRecoveryJobsV4) Inspect(context.Context, configpoc.SelectionReferenceV2) (bool, error) {
	return true, nil
}
func (j dhcpRecoveryJobsV4) Dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	return j.r.dispatch(ctx, c)
}
func (j dhcpRecoveryJobsV4) Invalidate(ctx context.Context) error {
	j.r.mu.Lock()
	defer j.r.mu.Unlock()
	return j.r.closeUnder(ctx)
}

type dhcpRecoveryTraceJobsV4 struct {
	dhcpRecoveryJobsV4
	commands chan firewallipc.RoutedCommandV3
}

func (j dhcpRecoveryTraceJobsV4) Dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	j.commands <- c
	return j.dhcpRecoveryJobsV4.Dispatch(ctx, c)
}

func TestRoutedDHCPV4RecoveryControllerRevokesBeforeCurrentAndRetainsWork(t *testing.T) {
	for _, mode := range []string{"owner-unavailable", "changed-tuple", "closed-channel"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
				t.Fatal(err)
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
			writer := &dhcpRecoveryWriterV4{r: r, k: k, reader: reader}
			s, err := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
			if err != nil {
				t.Fatal(err)
			}
			s.integrity = &routedIntegrityGateV3{}
			commands := make(chan firewallipc.RoutedCommandV3, 8)
			s.dhcpJobs = dhcpRecoveryTraceJobsV4{dhcpRecoveryJobsV4{r}, commands}
			controller := dhcpRecoveryControllerSessionV4(t, r, writer, s)
			controller.recoveryOnly = true
			switch mode {
			case "owner-unavailable":
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
					if r.opened || k.forward || k.gate {
						t.Error("controller queried owner before revoking")
					}
					return RoutedDHCPOwnerFactV3{}, ErrUnavailable
				}
			case "changed-tuple":
				next := dhcpRuntimeRenewedSnapshotV4(t, grant.Snapshot)
				next.Address, next.Hash = "198.19.0.9/24", ""
				data, _ := json.Marshal(next)
				digest := sha256.Sum256(data)
				next.Hash = hex.EncodeToString(digest[:])
				next, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(next)
				if err != nil {
					t.Fatal(err)
				}
				*fact = RoutedDHCPOwnerFactV3{Epoch: grant.Epoch + 1, Fact: next.Fact()}
				k.snapshot = next
			case "closed-channel":
				if err = controller.remote.client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			k.events = nil
			err = controller.Reconcile(ctx)
			if !errors.Is(err, configpoc.ErrRecovery) || !controller.recoveryOnly || controller.work != work.hash || r.work != work.hash || writer.archived != 0 || writer.prepared != 0 || !k.target || !reflect.DeepEqual(r.grant, grant) || !reflect.DeepEqual(controller.grant, grant) {
				t.Fatal("recovery changed store, authority, or ownership", err)
			}
			if mode == "closed-channel" {
				if !errors.Is(err, firewallipc.ErrChannel) || len(commands) != 0 {
					t.Fatal("nonrecoverable channel failure continued reconciliation", err)
				}
			} else {
				if r.opened || k.gate || k.forward || len(commands) != 2 {
					t.Fatal("recovery did not close or emitted unexpected RPCs")
				}
				first, second := <-commands, <-commands
				if first.Verb != "dhcp_renew" || first.DHCP.Work != work.hash || first.DHCP.Snapshot != grant.Snapshot.Hash || !first.DHCP.RefreshOnly || second.Verb != "dhcp_current" {
					t.Fatal("revocation did not precede Current with retained correlation")
				}
			}
			for _, event := range k.events {
				if event == "open" || event == "stage" || event == "forward-on" || event == "L3-add" || event == "L3-withdraw" {
					t.Fatal("recovery performed forbidden effect", event)
				}
			}
		})
	}
}

type dhcpRecoveryObservedV4 struct {
	configpoc.RoutedAuthorityV1
	r        *RoutedDHCPRuntimeV3
	required string // Protected by r.mu; models the physical retained-proof check.
}

func (a *dhcpRecoveryObservedV4) Observe(ctx context.Context) (configpoc.RoutedReceiptV1, string, error) {
	a.r.mu.Lock()
	stale := a.required != "" && a.r.grant.Snapshot.Hash != a.required
	a.r.mu.Unlock()
	if stale {
		return configpoc.RoutedReceiptV1{}, "", configpoc.ErrRecovery
	}
	return a.RoutedAuthorityV1.Observe(ctx)
}

func TestRoutedDHCPV4InspectionSchedulerRecoversOnlyAfterClosedRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, k, reader, fact := dhcpRuntimeFixtureV3(t)
		ctx := context.Background()
		if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
			t.Fatal(err)
		}
		s, integrityReader, _ := integritySessionFixtureV3(t)
		observed := &dhcpRecoveryObservedV4{RoutedAuthorityV1: s.authority, r: r}
		s.authority, s.dhcpJobs = observed, dhcpRecoveryJobsV4{r}
		writer := &dhcpRecoveryWriterV4{r: r, k: k, reader: reader}
		controller := dhcpRecoveryControllerSessionV4(t, r, writer, s)
		defer controller.closeSchedulerV4()
		remote, err := NewRoutedRemoteIntegrityV3(controller.remote.client)
		if err != nil {
			t.Fatal(err)
		}
		if err = remote.Attach(ctx, integrityReader.ref); err != nil {
			t.Fatal(err)
		}
		if result, e := remote.Inspect(ctx, integrityReader.ref); e != nil || result.State != configpoc.IntegrityCompleteV1 {
			t.Fatal("initial full inspection", result, e)
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
		next := configpoc.RoutedDHCPGrantV3{Epoch: grant.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, grant.Snapshot)}
		*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
		k.snapshot, observed.required = next.Snapshot, next.Snapshot.Hash
		proofs := 0
		r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
			if k.forward || k.gate || r.opened || !k.target {
				return configpoc.ErrRecovery
			}
			proofs++
			return nil
		}}
		ticks, inspected := make(chan time.Time), make(chan error, 1)
		schedulerCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			runRoutedIntegritySchedulerV3(schedulerCtx, ticks, nil, func(call context.Context) error {
				controller.mu.Lock()
				defer controller.mu.Unlock()
				result, e := remote.Inspect(call, integrityReader.ref)
				if e == nil && result.State != configpoc.IntegrityCompleteV1 {
					e = configpoc.ErrRecovery
				}
				controller.afterInspectionV4(e, controller.remote.client.DHCPSelectedV4())
				inspected <- e
				return e
			})
		}()
		defer func() { cancel(); <-done }()
		ticks <- time.Now()
		if e := <-inspected; !errors.Is(e, configpoc.ErrRecovery) {
			t.Fatal("stale proof passed full inspection", e)
		}
		time.Sleep(500 * time.Millisecond) // First admission may lose TryLock to inspection.
		synctest.Wait()
		r.mu.Lock()
		closed := !r.opened && !k.gate && !k.forward && k.target && reflect.DeepEqual(r.grant, next) && proofs == 1
		r.mu.Unlock()
		if !closed || r.ready() == nil {
			t.Fatal("scheduler did not refresh under incomplete inspection with gates closed")
		}
		ticks <- time.Now()
		if e := <-inspected; e != nil {
			t.Fatal("refreshed physical proof did not pass full inspection", e)
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		r.mu.Lock()
		opened := r.opened && k.gate && k.forward && k.target && reflect.DeepEqual(r.grant, next) && proofs == 1
		opens, forwards := 0, 0
		for _, event := range k.events {
			if event == "open" {
				opens++
			}
			if event == "forward-on" {
				forwards++
			}
		}
		r.mu.Unlock()
		if !opened || opens != 2 || forwards != 2 || r.ready() != nil || writer.archived != 0 || writer.prepared != 0 || controller.work != work.hash || !reflect.DeepEqual(work.grant, grant) {
			t.Fatal("qualified scheduler did not open unchanged Work exactly once")
		}
	})
}

func TestRoutedDHCPV4UnknownCurrentPreservesSelectedWork(t *testing.T) {
	r, k, reader, _ := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
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
	writer := &dhcpRecoveryWriterV4{r: r, k: k, reader: reader}
	controller := dhcpRecoveryControllerV4(t, r, writer)
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return RoutedDHCPOwnerFactV3{}, ErrUnavailable }
	if err = controller.Reconcile(ctx); err == nil {
		t.Fatal("unknown observation classified as withdrawal", err)
	}
	if controller.work != work.hash || r.work != work.hash || writer.archived != 0 || writer.prepared != 0 || !k.target {
		t.Fatal("uncertainty destroyed selected L3")
	}
}

func TestRoutedDHCPV4RefreshOnlyClosesEvenWhenReadyAndGrantUnchanged(t *testing.T) {
	r, k, reader, _ := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
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
	k.events = nil
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = r.renewSameEffectiveModeV4(ctx, work.hash, grant.Snapshot.Hash, true); err == nil {
			t.Fatal("refresh-only reported opening success")
		}
		if r.opened || k.forward || k.gate || !k.target || !r.renewalWaiting {
			t.Fatal("refresh-only changed L3 or opened permission")
		}
	}
	for _, event := range k.events {
		if event == "open" || event == "stage" || event == "forward-on" || event == "L3-add" || event == "L3-withdraw" {
			t.Fatal("refresh-only performed forbidden effect", event)
		}
	}
	if !reflect.DeepEqual(r.grant, grant) || r.verifyClosed(ctx, grant.Snapshot.Hash, networkexecutor.LeaseSelectedTargetV3) != nil {
		t.Fatal("lost retained evidence")
	}
}

type dhcpRefreshFailureGateV4 struct {
	routedDHCPGateV3
	closeErr, readbackErr error
}

func (g dhcpRefreshFailureGateV4) Close(ctx context.Context) error {
	if g.closeErr != nil {
		return g.closeErr
	}
	return g.routedDHCPGateV3.Close(ctx)
}

func (g dhcpRefreshFailureGateV4) VerifyClosedSelectedV3(ctx context.Context) error {
	if g.readbackErr != nil {
		return g.readbackErr
	}
	return g.routedDHCPGateV3.VerifyClosedSelectedV3(ctx)
}

func TestRoutedDHCPV4RefreshOnlyRevokesBeforeFallibleChecks(t *testing.T) {
	for _, mode := range []string{"checking", "owner-unavailable", "snapshot-mismatch", "fenced", "close-uncertain", "readback-uncertain", "wrong-work", "legacy-profile"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, _ := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			if mode != "legacy-profile" {
				if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
					t.Fatal(err)
				}
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
			requestWork, snapshot := work.hash, grant.Snapshot.Hash
			uncertain := errors.New("closure evidence unavailable")
			assertRevoked := func() {
				if k.gate || k.forward || r.opened {
					t.Error("fallible check preceded revocation")
				}
			}
			switch mode {
			case "checking":
				r.ready = func() error { assertRevoked(); return configpoc.ErrRecovery }
				r.refreshReady = func() bool { assertRevoked(); return false }
			case "owner-unavailable":
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
					assertRevoked()
					return RoutedDHCPOwnerFactV3{}, ErrUnavailable
				}
			case "snapshot-mismatch":
				snapshot = strings.Repeat("f", 64)
			case "fenced":
				r.fenced = func() bool { assertRevoked(); return true }
			case "close-uncertain":
				r.gate = dhcpRefreshFailureGateV4{routedDHCPGateV3: r.gate, closeErr: uncertain}
			case "readback-uncertain":
				r.gate = dhcpRefreshFailureGateV4{routedDHCPGateV3: r.gate, readbackErr: uncertain}
			case "wrong-work":
				requestWork = strings.Repeat("f", 64)
			}
			k.events = nil
			if _, err = r.renewSameEffectiveModeV4(ctx, requestWork, snapshot, true); err == nil {
				t.Fatal("failed refresh-only request reported success")
			}
			if mode == "wrong-work" || mode == "legacy-profile" {
				if !r.opened || !k.gate || !k.forward || len(k.events) != 0 {
					t.Fatal("unbound request mutated another authority")
				}
			} else if mode == "close-uncertain" || mode == "readback-uncertain" {
				if !errors.Is(err, uncertain) || !r.failed || r.opened || k.forward {
					t.Fatal("uncertain closure error was lost or not contained", err)
				}
			} else if r.opened || k.gate || k.forward || !r.renewalWaiting {
				t.Fatal("refresh-only failed before closing the existing permit")
			}
			if !k.target || !reflect.DeepEqual(r.grant, grant) || !reflect.DeepEqual(work.grant, grant) || r.work != work.hash {
				t.Fatal("closure-only request changed selected work or evidence")
			}
			for _, event := range k.events {
				if event == "open" || event == "stage" || event == "forward-on" || event == "L3-add" || event == "L3-withdraw" {
					t.Fatal("failed refresh-only performed forbidden effect", event)
				}
			}
		})
	}
}

func TestRoutedDHCPV4InspectionFailureSchedulerClosesUnchangedLiveGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, k, reader, _ := dhcpRuntimeFixtureV3(t)
		ctx := context.Background()
		if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
			t.Fatal(err)
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
		writer := &dhcpRecoveryWriterV4{r: r, k: k, reader: reader}
		controller := dhcpRecoveryControllerV4(t, r, writer)
		defer controller.closeSchedulerV4()
		// Failure before the inspection RPC leaves the helper Ready and open.
		// The production callback, without a manual Reconcile, must close it.
		controller.mu.Lock()
		controller.afterInspectionV4(ErrUnavailable, true)
		controller.mu.Unlock()
		synctest.Wait()
		r.mu.Lock()
		closed := !r.opened && !k.gate && !k.forward && k.target && r.renewalWaiting
		r.mu.Unlock()
		if !closed || writer.prepared != 0 || writer.archived != 0 {
			t.Fatal("failed inspection scheduler preserved a live token or changed selected Work")
		}
		controller.mu.Lock()
		err = controller.reconcileLocked(ctx)
		controller.mu.Unlock()
		if !errors.Is(err, configpoc.ErrRecovery) {
			t.Fatal("closed-only retry reported success", err)
		}
	})
}
