//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routednft"
	"golang.org/x/sys/unix"
)

// Real private datagrams/SCM_RIGHTS/credentials, with an explicitly fake owner.
// These tests do not acquire a DHCP lease, mount or configure a namespace.
type jobOwnerFixtureV4 struct {
	binding        RoutedDHCPDeferredBindingV4
	files          RoutedDHCPDeferredFilesV4
	others         []*os.File
	active, closed atomic.Int32
	done           chan struct{}
}

func (o *jobOwnerFixtureV4) TakeReaderFiles() (RoutedDHCPDeferredFilesV4, RoutedDHCPDeferredBindingV4, error) {
	f := o.files
	o.files = RoutedDHCPDeferredFilesV4{}
	return f, o.binding, nil
}
func (o *jobOwnerFixtureV4) Activate(context.Context) error { o.active.Add(1); return nil }
func (o *jobOwnerFixtureV4) Close() error {
	if o.closed.CompareAndSwap(0, 1) {
		_ = o.files.Close()
		for _, f := range o.others {
			_ = f.Close()
		}
		close(o.done)
	}
	return nil
}
func (o *jobOwnerFixtureV4) Done() <-chan struct{} { return o.done }

func newJobOwnerFixtureV4(t *testing.T) *jobOwnerFixtureV4 {
	t.Helper()
	binding, _ := routedDeferredFixtureV4(t)
	a, b, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	c, d, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	o := &jobOwnerFixtureV4{binding: binding, files: RoutedDHCPDeferredFilesV4{Request: b, Reply: c, ProducerPIDFD: os.NewFile(uintptr(fd), "test-pidfd")}, others: []*os.File{a, d}, done: make(chan struct{})}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func jobSourceFixtureV4(t *testing.T, binding RoutedDHCPDeferredBindingV4) (Metadata, configpoc.RoutedWorkReferenceV1, RoutedSelectedPreflightResultV4) {
	t.Helper()
	m := Metadata{SchemaVersion: 2, RunID: binding.Owner.RunID, BootID: binding.Owner.BootID, HostNamespace: 11, GatewayNamespace: binding.Owner.Namespace}
	work := configpoc.RoutedWorkReferenceV1{Work: strings.Repeat("a", 64), Lineage: "selected-lineage", Generation: 4}
	policy := routednft.LabPolicy()
	policy.Network = binding.Desired
	source := RoutedSelectedPreflightResultV4{Work: work, Resolution: "target", Reference: configpoc.SelectionReferenceV2{Selection: strings.Repeat("b", 64), State: strings.Repeat("c", 64), WorkHash: work.Work, Lineage: work.Lineage, Generation: work.Generation, Mode: "active"}, Bundle: configpoc.RoutedActivationBundleV1{Firewall: configpoc.Revision{Config: configpoc.Config{Routed: &policy}}}}
	return m, work, source
}

func jobChannelFixtureV4(t *testing.T) (*net.UnixConn, *net.UnixConn, routedDHCPJobPeerV4) {
	t.Helper()
	root, file, err := routedDHCPJobPairV4()
	if err != nil {
		t.Fatal(err)
	}
	helper, err := routedDHCPJobSocketV4(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close(); _ = helper.Close() })
	return root, helper, routedDHCPJobPeerV4{pid: os.Getpid(), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
}

func TestRoutedDHCPJobsV4PrivatePrepareActivateStop(t *testing.T) {
	o := newJobOwnerFixtureV4(t)
	m, work, source := jobSourceFixtureV4(t, o.binding)
	var reads atomic.Int32
	b := &routedDHCPJobBrokerV4{preflight: func(_ context.Context, w configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error) {
		reads.Add(1)
		if w != work {
			return RoutedSelectedPreflightResultV4{}, ErrIdentity
		}
		return source, nil
	}, prepare: func(_ context.Context, r networkplan.Revision) (routedDHCPJobOwnerV4, error) {
		if r.Hash != o.binding.Desired.Hash {
			t.Error("caller plan")
		}
		return o, nil
	}}
	r, h, peer := jobChannelFixtureV4(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.serve(ctx, r, m, peer) }()
	client := &routedDHCPJobClientV4{conn: h, metadata: m, peer: peer}
	reply, files, err := client.call(ctx, "prepare", work)
	if err != nil || reply.Binding == nil || len(files) != 3 || o.active.Load() != 0 {
		t.Fatal("standby capability", err, len(files))
	}
	for _, f := range files {
		if _, err = f.Stat(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	if _, _, err = client.call(ctx, "activate", work); err != nil || o.active.Load() != 1 || reads.Load() != 4 {
		t.Fatal("activation/revalidation", err, reads.Load())
	}
	if _, _, err = client.call(ctx, "stop", work); err != nil || o.closed.Load() != 1 {
		t.Fatal("stop", err)
	}
	_ = client.Close()
	<-done
}

func TestRoutedDHCPJobsV4RejectsChangedSelectionWithoutGrant(t *testing.T) {
	for _, at := range []int{2, 4} {
		t.Run(map[int]string{2: "after prepare", 4: "after activate"}[at], func(t *testing.T) {
			o := newJobOwnerFixtureV4(t)
			m, work, source := jobSourceFixtureV4(t, o.binding)
			n := 0
			b := &routedDHCPJobBrokerV4{preflight: func(context.Context, configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error) {
				n++
				s := source
				if n == at {
					s.Reference.Sequence++
				}
				return s, nil
			}, prepare: func(context.Context, networkplan.Revision) (routedDHCPJobOwnerV4, error) { return o, nil }}
			q := routedDHCPJobV4{4, m.RunID, m.GatewayNamespace, 1, "prepare", work}
			_, files, err := b.dispatch(context.Background(), q)
			for _, f := range files {
				_ = f.Close()
			}
			if at == 4 {
				if err != nil {
					t.Fatal(err)
				}
				q.Operation = "activate"
				_, files, err = b.dispatch(context.Background(), q)
				for _, f := range files {
					_ = f.Close()
				}
			}
			if err == nil || o.closed.Load() != 1 {
				t.Fatal("changed selection kept owner", err)
			}
		})
	}
}

func TestRoutedDHCPJobsV4CredentialFDAndReplayBoundaries(t *testing.T) {
	for _, kind := range []string{"wrong peer", "extra fd", "replay", "bad frame", "EOF"} {
		t.Run(kind, func(t *testing.T) {
			o := newJobOwnerFixtureV4(t)
			m, work, source := jobSourceFixtureV4(t, o.binding)
			b := &routedDHCPJobBrokerV4{preflight: func(context.Context, configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error) {
				return source, nil
			}, prepare: func(context.Context, networkplan.Revision) (routedDHCPJobOwnerV4, error) { return o, nil }}
			r, h, peer := jobChannelFixtureV4(t)
			want := peer
			if kind == "wrong peer" {
				want.pid++
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- b.serve(ctx, r, m, want) }()
			q := routedDHCPJobV4{4, m.RunID, m.GatewayNamespace, 1, "prepare", work}
			switch kind {
			case "bad frame":
				_, _ = h.Write([]byte(`{"version":4,"version":4}`))
			case "extra fd":
				if err := routedDHCPJobSendV4(h, q, []*os.File{o.files.ProducerPIDFD}); err != nil {
					t.Fatal(err)
				}
			case "wrong peer":
				if err := routedDHCPJobSendV4(h, q, nil); err != nil {
					t.Fatal(err)
				}
			default:
				if err := routedDHCPJobSendV4(h, q, nil); err != nil {
					t.Fatal(err)
				}
				var reply routedDHCPJobReplyV4
				files, err := routedDHCPJobReceiveV4(h, peer, &reply)
				for _, f := range files {
					_ = f.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				if kind == "EOF" {
					_ = h.Close()
				} else {
					if err := routedDHCPJobSendV4(h, q, nil); err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid channel accepted")
				}
			case <-ctx.Done():
				t.Fatal("channel did not drain")
			}
			if (kind == "EOF" || kind == "replay") && o.closed.Load() != 1 {
				t.Fatal("owner survived channel loss")
			}
		})
	}
}

type jobInspectionFixtureV4 struct {
	calls       int
	fail        bool
	invalidated int
}

func (h *jobInspectionFixtureV4) Invalidate(context.Context) error { h.invalidated++; return nil }

func (h *jobInspectionFixtureV4) Inspect(context.Context, configpoc.SelectionReferenceV2) (bool, error) {
	h.calls++
	if h.fail {
		return false, ErrUnavailable
	}
	return true, nil
}
func (*jobInspectionFixtureV4) Dispatch(context.Context, firewallipc.RoutedCommandV3) (any, error) {
	return nil, ErrUnavailable
}

func TestRoutedDHCPJobsV4OnlyCompleteInspectionMayActivate(t *testing.T) {
	ctx := context.Background()
	s, reader, _ := integritySessionFixtureV3(t)
	hook := &jobInspectionFixtureV4{}
	s.dhcpJobs = hook
	attach := firewallipc.RoutedCommandV3{Verb: "inspect", Integrity: firewallipc.RoutedIntegrityV3{Mode: "attach", Selection: reader.ref}}
	if _, err := s.dispatch(ctx, attach); err != nil || hook.calls != 0 {
		t.Fatal("attach activated", err)
	}
	check := attach
	check.Integrity.Mode = "check"
	reader.state = configpoc.IntegrityUnavailableV1
	if _, err := s.dispatch(ctx, check); err != nil || hook.calls != 0 {
		t.Fatal("incomplete activated", err)
	}
	if hook.invalidated != 1 {
		t.Fatal("incomplete inspection did not close effective grant")
	}
	reader.state = configpoc.IntegrityCompleteV1
	result, err := s.dispatch(ctx, check)
	if err != nil || hook.calls != 1 || !result.(firewallipc.RoutedIntegrityResultV3).DHCPSelected {
		t.Fatal("complete hook", err)
	}
	hook.fail = true
	result, err = s.dispatch(ctx, check)
	if !errors.Is(err, ErrUnavailable) || result.(firewallipc.RoutedIntegrityResultV3).Result.State == configpoc.IntegrityCompleteV1 || result.(firewallipc.RoutedIntegrityResultV3).DHCPSelected {
		t.Fatal("failed activation claimed readiness", err)
	}
}
