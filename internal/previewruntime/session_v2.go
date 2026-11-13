package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

// SessionV2 is a fixed-protocol helper authority. It cannot dispatch v1 verbs.
// A session survives controller loss, including its independent guardian lease.
type SessionV2 struct {
	controller             sync.Mutex
	mu                     sync.Mutex
	base                   *Session
	domain                 string
	epoch, last            uint64
	active, attached, cold bool
	readOnly               bool
	routedReadback         routedLegacyReadbackV3
	routedOwner            *RoutedAuthority
}

func NewSessionV2(run string, namespace uint64, engine Engine, guardian *nftguardian.Guardian, observe Observer) (*SessionV2, error) {
	if !ValidRun(run) || namespace == 0 || engine == nil || guardian == nil || observe == nil {
		return nil, errHelper
	}
	return &SessionV2{base: NewSession(run, namespace, engine, guardian, observe), domain: "firewall"}, nil
}

// NewRoutedCompatibilitySessionV2 exposes only observation to a grouped writer.
// All effects belong to the independently selected v3 authority. This choice
// is fixed for the session lifetime and cannot be changed by a wire request.
func NewRoutedCompatibilitySessionV2(run string, namespace uint64, engine Engine, guardian *nftguardian.Guardian, observe Observer) (*SessionV2, error) {
	s, err := NewSessionV2(run, namespace, engine, guardian, observe)
	if err != nil {
		return nil, err
	}
	s.readOnly = true
	return s, nil
}
func NewLocalSessionV2(run string, namespace uint64, engine Engine, guardian *nftguardian.Guardian, compile firewallipc.Compiler, observe func(context.Context) (string, localpolicy.Observation, error)) (*SessionV2, error) {
	b, e := NewLocalSession(run, namespace, engine, guardian, compile, observe)
	if e != nil {
		return nil, e
	}
	return &SessionV2{base: b, domain: "local_services"}, nil
}
func stateV2(s nftguardian.State) firewalladmin.LeaseState {
	return firewalladmin.LeaseState{Phase: s.Phase, ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}
}

// ServeV2 requires assembly-authenticated channel provenance. The Unix wrappers
// perform kernel peer checks; no public runtime selects this prepared session.
func (s *SessionV2) ServeV2(ctx context.Context, conn io.ReadWriteCloser, runtimeRun string) error {
	if s == nil || s.base == nil || (s.routedReadback == nil && (s.base.guardian == nil || s.base.engine == nil)) || (s.routedReadback != nil && (!s.readOnly || s.domain != "firewall")) || !firewallipc.DomainV2(s.domain) || ctx == nil || conn == nil || !ValidRun(runtimeRun) {
		if conn != nil {
			_ = conn.Close()
		}
		return errHelper
	}
	if !s.controller.TryLock() {
		_ = conn.Close()
		return errHelper
	}
	defer s.controller.Unlock()
	s.mu.Lock()
	if s.active || s.epoch == 0xffffffff {
		s.mu.Unlock()
		_ = conn.Close()
		return errHelper
	}
	s.active = true
	s.epoch++
	epoch := s.epoch
	s.last = epoch << 32
	s.attached = false
	s.cold = false
	s.mu.Unlock()
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		s.active = false
		s.attached = false
		s.cold = false
		s.mu.Unlock()
	}()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	reader := bufio.NewReaderSize(conn, firewallipc.MaxFrame)
	read := func(first bool) ([]byte, error) {
		if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			if !first {
				_ = d.SetReadDeadline(time.Time{})
				if _, e := reader.Peek(1); e != nil {
					return nil, e
				}
			}
			_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		b, e := reader.ReadSlice('\n')
		if e != nil || len(b) > firewallipc.MaxFrame {
			return nil, errHelper
		}
		return b, nil
	}
	write := func(v any) error {
		data, e := json.Marshal(v)
		limit := firewallipc.MaxFrame
		if s.domain == "local_services" {
			limit = firewallipc.LocalReplyMaxFrame
		}
		if e != nil || len(data)+1 > limit {
			return errHelper
		}
		if d, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = d.SetWriteDeadline(time.Now().Add(3 * time.Second))
		}
		frame := append(data, '\n')
		n, e := conn.Write(frame)
		if e == nil && n != len(frame) {
			return io.ErrShortWrite
		}
		return e
	}
	b, e := read(true)
	if e != nil {
		return errHelper
	}
	h, e := firewallipc.DecodeHelloV2(b, false)
	if e != nil || h.RuntimeRun != runtimeRun || h.Namespace != s.base.namespace || h.Domain != s.domain {
		return errHelper
	}
	h.Run = s.base.run
	h.Epoch = epoch
	if write(h) != nil {
		return errHelper
	}
	for {
		b, e = read(false)
		if e != nil {
			return errHelper
		}
		m, p, e := firewallipc.DecodeRequestV2(b)
		if e != nil {
			return errHelper
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		reply, e := s.handleV2(call, epoch, m, p)
		cancel()
		if e != nil || write(reply) != nil {
			return errHelper
		}
	}
}

func (s *SessionV2) handleV2(ctx context.Context, epoch uint64, m firewallipc.RequestV2, p firewallipc.CommandV2) (firewallipc.ReplyV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.base
	if !s.active || m.ProtocolVersion != 2 || m.Domain != s.domain || m.Run != b.run || m.Namespace != b.namespace || epoch != s.epoch || m.Sequence>>32 != epoch || m.Sequence != s.last+1 || m.Sequence&0xffffffff == 0 {
		return firewallipc.ReplyV2{}, errHelper
	}
	s.last = m.Sequence
	if s.routedReadback != nil {
		return s.handleRoutedReadbackV3(ctx, m, p)
	}
	reply := firewallipc.ReplyV2{ProtocolVersion: 2, Run: m.Run, Sequence: m.Sequence, Namespace: m.Namespace, Domain: m.Domain, Verb: m.Verb}
	result := firewallipc.ResultV2{}
	var err error
	if s.readOnly && m.Verb != "state" && m.Verb != "observe" && m.Verb != "attach_observed" {
		err = errHelper
	}
	if m.Verb != "state" && m.Verb != "observe" && m.Verb != "attach_observed" && (!s.attached || (s.cold && m.Verb != "bootstrap")) {
		err = errHelper
	}
	if err == nil {
		switch m.Verb {
		case "state":
		case "attach_observed":
			o := p.Observed
			err = b.guardian.MatchObserved(nftguardian.State{Phase: o.State.Phase, ID: o.State.ID, Previous: o.State.Previous, Target: o.State.Target, Deadline: o.State.Deadline}, o.Hash)
			if err == nil {
				s.attached = true
				s.cold = o.State.Phase == "bootstrap"
				result.State = o.State
				result.Hash = o.Hash
				result.ObservedScope = &o
			}
		case "bootstrap":
			if !s.cold || !b.validRevision(p.Revision) {
				err = errHelper
			} else {
				err = b.guardian.Bootstrap(ctx, p.Revision)
			}
			if err == nil {
				s.cold = false
			}
		case "apply":
			if !b.validRevision(p.Revision) {
				err = errHelper
			} else {
				err = b.guardian.Apply(ctx, p.Revision)
			}
		case "arm":
			if !b.validRevision(p.Arm.Previous) || !b.validRevision(p.Arm.Target) {
				err = errHelper
			} else {
				err = b.guardian.Arm(p.Arm.ID, p.Arm.Previous, p.Arm.Target, p.Arm.TTL)
			}
		case "arm_until":
			if !b.validRevision(p.ArmUntil.Previous) || !b.validRevision(p.ArmUntil.Target) {
				err = errHelper
			} else {
				err = b.guardian.ArmUntil(p.ArmUntil.ID, p.ArmUntil.Previous, p.ArmUntil.Target, p.ArmUntil.Deadline)
			}
		case "apply_scoped":
			scope := p.ApplyScoped.Scope
			if !b.validRevision(p.ApplyScoped.Revision) {
				err = errHelper
			} else {
				err = b.guardian.ApplyLease(ctx, p.ApplyScoped.Revision, nftguardian.State{ID: scope.ID, Previous: scope.Previous, Target: scope.Target, Deadline: scope.Deadline})
			}
		case "confirm_scoped":
			scope := p.Recovery
			err = b.guardian.ConfirmLease(nftguardian.State{ID: scope.ID, Previous: scope.Previous, Target: scope.Target, Deadline: scope.Deadline})
		case "confirm":
			err = b.guardian.Confirm(p.Confirm.ID, p.Confirm.Target)
		case "recover_scoped":
			err = b.guardian.RecoverLease(p.Recovery.ID, p.Recovery.Previous, p.Recovery.Target, p.Recovery.Deadline)
			if err == nil {
				scope := p.Recovery
				result.RecoveryScope = &scope
			}
		case "observe":
			if b.localObserve != nil {
				var observed localpolicy.Observation
				result.Hash, observed, err = b.localObserve(ctx)
				if err == nil {
					result.Local = &observed
				}
			} else {
				result.Hash, result.Counters, result.CounterEpoch, err = b.observe(ctx)
			}
			if err == nil && (result.Hash == "" || b.engine.Current() != result.Hash) {
				err = errHelper
			}
		default:
			err = errHelper
		}
	}
	if err == nil && m.Verb != "attach_observed" {
		var state nftguardian.State
		var hash string
		state, hash, err = b.guardian.SnapshotObserved()
		if err == nil {
			result.State = stateV2(state)
			if m.Verb == "observe" && result.Hash != hash {
				err = errHelper
			}
			result.Hash = hash
		}
	}
	if err == nil && (m.Verb == "apply" || m.Verb == "bootstrap" || m.Verb == "arm" || m.Verb == "arm_until" || m.Verb == "apply_scoped") {
		r := p.Revision
		if m.Verb == "arm" {
			r = p.Arm.Target
		}
		if m.Verb == "arm_until" {
			r = p.ArmUntil.Target
		}
		if m.Verb == "apply_scoped" {
			r = p.ApplyScoped.Revision
		}
		result.Artifact, err = b.digest(r.Config)
	}
	if err == nil && m.Verb == "bootstrap" && (result.State.Phase != "idle" || result.State.ID != "" || result.Hash != p.Revision.Hash) {
		err = errHelper
		s.attached = false
	}
	if err == nil && m.Verb == "recover_scoped" && (result.State.Phase != "idle" || result.State.ID != "" || result.Hash != p.Recovery.Previous) {
		err = errHelper
	}
	if err != nil {
		reply.Error = errHelper.Error()
		reply.Payload = json.RawMessage(`{}`)
	} else {
		reply.Payload, err = json.Marshal(result)
		if err != nil {
			return firewallipc.ReplyV2{}, errHelper
		}
	}
	return reply, nil
}
