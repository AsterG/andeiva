package previewruntime

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type compensationSourceFixtureV3 struct {
	routedTransportReaderV3
	prepared, consumed         configpoc.SelectionReferenceV2
	prepareReads, consumeReads int
	denyPrepare                bool
}

func (f *compensationSourceFixtureV3) resolveCompensationV3(_ context.Context, p firewallipc.RoutedCompensationV3) (configpoc.RoutedCompensationAuthorizationV1, error) {
	f.prepareReads++
	if f.denyPrepare || p.Selection != f.prepared {
		return configpoc.RoutedCompensationAuthorizationV1{}, configpoc.ErrRecovery
	}
	return configpoc.RoutedCompensationAuthorizationV1{}, nil
}

func (f *compensationSourceFixtureV3) resolveConsumedCompensationV3(_ context.Context, _ configpoc.RoutedCompensationAuthorizationV1, selected configpoc.SelectionReferenceV2) (configpoc.RoutedCompensationAuthorizationV1, error) {
	f.consumeReads++
	if selected != f.consumed {
		return configpoc.RoutedCompensationAuthorizationV1{}, configpoc.ErrRecovery
	}
	return configpoc.RoutedCompensationAuthorizationV1{}, nil
}

type compensationAuthorityFixtureV3 struct {
	routedTransportAuthorityV3
	effects int
}

func (f *compensationAuthorityFixtureV3) recoverCompensationV3(context.Context, configpoc.RoutedCompensationAuthorizationV1) error {
	f.effects++
	return nil
}

func compensationFixtureV3(t *testing.T) (*RoutedSessionV3, *compensationSourceFixtureV3, *compensationAuthorityFixtureV3, configpoc.RoutedWorkReferenceV1) {
	t.Helper()
	selected := integrityRefFixtureV3()
	selected.Mode, selected.WorkHash = "pending", strings.Repeat("a", 64)
	consumed := selected
	consumed.Previous = selected.Selection
	consumed.Selection = strings.Repeat("d", 64)
	consumed.Sequence++
	source := &compensationSourceFixtureV3{prepared: selected, consumed: consumed}
	authority := &compensationAuthorityFixtureV3{}
	session, err := NewRoutedSessionV3(authority, source)
	if err != nil {
		t.Fatal(err)
	}
	session.integrity = &routedIntegrityGateV3{fence: &integrityMarkerFixtureV3{}, anchor: selected, phase: routedIntegrityReadyV3}
	work := configpoc.RoutedWorkReferenceV1{Work: selected.WorkHash, Lineage: selected.Lineage, Generation: selected.Generation}
	return session, source, authority, work
}

func TestRoutedCompensationV3ConnectionAndReplay(t *testing.T) {
	s, source, authority, work := compensationFixtureV3(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connect := func() (*RoutedRemoteAuthority, <-chan error) {
		t.Helper()
		a, b := net.Pipe()
		finished := make(chan error, 1)
		id := authority.Identity()
		go func() { finished <- s.ServeRoutedV3(ctx, b, id.RunID) }()
		client, err := firewallipc.ConnectRoutedIntegrityV3(ctx, a, id.RunID, id.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := NewRoutedRemoteAuthority(client, id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = remote.Close() })
		return remote, finished
	}
	first, finished := connect()
	ticket, err := first.PrepareCompensationV3(ctx, work, source.prepared, "operation")
	if err != nil || ticket == "" {
		t.Fatal("prepare failed", err)
	}
	_ = first.Close()
	<-finished
	if authority.effects != 0 || source.prepareReads != 1 || source.consumeReads != 0 {
		t.Fatal("preparation had effects")
	}

	second, finished := connect()
	if err := second.RecoverCompensationV3(ctx, work, source.consumed, "operation", ticket); !errors.Is(err, configpoc.ErrRecovery) {
		t.Fatal("replaced connection accepted old ticket", err)
	}
	ticket, err = second.PrepareCompensationV3(ctx, work, source.prepared, "operation")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.RecoverCompensationV3(ctx, work, source.consumed, "operation", ticket); err != nil {
		t.Fatal("recover failed", err)
	}
	if err := second.RecoverCompensationV3(ctx, work, source.consumed, "operation", ticket); !errors.Is(err, configpoc.ErrRecovery) {
		t.Fatal("replayed handoff accepted", err)
	}
	_ = second.Close()
	<-finished
	if authority.effects != 1 || source.prepareReads != 2 || source.consumeReads != 1 {
		t.Fatal("an unmatched ticket reached verified recovery")
	}
}

func TestRoutedCompensationV3RefusalsInvalidateWithoutEffects(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*routedCompensationHandoffV3, *firewallipc.RoutedCompensationV3, *compensationSourceFixtureV3)
		reprepare bool
		reads     int
	}{
		{name: "another operation", change: func(_ *routedCompensationHandoffV3, p *firewallipc.RoutedCompensationV3, _ *compensationSourceFixtureV3) {
			p.Operation = "another-operation"
		}},
		{name: "another work", change: func(_ *routedCompensationHandoffV3, p *firewallipc.RoutedCompensationV3, _ *compensationSourceFixtureV3) {
			p.Reference.Generation = "999"
		}},
		{name: "expired", change: func(h *routedCompensationHandoffV3, _ *firewallipc.RoutedCompensationV3, _ *compensationSourceFixtureV3) {
			h.expires = time.Now()
		}},
		{name: "unconsumed", reads: 1, change: func(_ *routedCompensationHandoffV3, p *firewallipc.RoutedCompensationV3, f *compensationSourceFixtureV3) {
			p.Selection = f.prepared
		}},
		{name: "repeated prepare", reprepare: true},
		{name: "failed prepare", reprepare: true, change: func(_ *routedCompensationHandoffV3, _ *firewallipc.RoutedCompensationV3, f *compensationSourceFixtureV3) {
			f.denyPrepare = true
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, source, authority, work := compensationFixtureV3(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var handoff routedCompensationHandoffV3
			p := compensationRequestV3(work, source.prepared, "operation", "")
			prepare := firewallipc.RoutedCommandV3{Verb: "prepare_recover", Compensation: &p}
			v, err := s.dispatchSessionV3(ctx, prepare, &handoff)
			if err != nil {
				t.Fatal(err)
			}
			req := compensationRequestV3(work, source.consumed, p.Operation, v.(firewallipc.RoutedCompensationPreparedV3).Ticket)
			original := req
			if tc.change != nil {
				tc.change(&handoff, &req, source)
			}
			if tc.reprepare {
				_, err := s.dispatchSessionV3(ctx, prepare, &handoff)
				var want error
				if source.denyPrepare {
					want = configpoc.ErrRecovery
				}
				if !errors.Is(err, want) {
					t.Fatal("unexpected repeated preparation result", err)
				}
			}
			for _, recover := range []firewallipc.RoutedCompensationV3{req, original} {
				if _, err := s.dispatchSessionV3(ctx, firewallipc.RoutedCommandV3{Verb: "recover", Compensation: &recover}, &handoff); !errors.Is(err, configpoc.ErrRecovery) {
					t.Fatal("invalid handoff accepted", err)
				}
			}
			if authority.effects != 0 || source.consumeReads != tc.reads || handoff.request.Ticket != "" {
				t.Fatal("refusal changed runtime or left an outstanding ticket")
			}
		})
	}
}

func TestRoutedCompensationV3RequiresConfiguredConsumer(t *testing.T) {
	s, source, _, work := compensationFixtureV3(t)
	s.authority = &routedTransportAuthorityV3{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p := compensationRequestV3(work, source.prepared, "operation", "")
	var handoff routedCompensationHandoffV3
	if _, err := s.dispatchSessionV3(ctx, firewallipc.RoutedCommandV3{Verb: "prepare_recover", Compensation: &p}, &handoff); !errors.Is(err, configpoc.ErrRecovery) {
		t.Fatal("published assembly without a consumer accepted compensation", err)
	}
	if source.prepareReads != 0 || handoff.request.Ticket != "" {
		t.Fatal("unavailable consumer left a prepared handoff")
	}
}
