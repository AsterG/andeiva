package previewruntime

import (
	"context"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

var errHelper = firewallipc.ErrChannel
var helperLease = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type Engine interface {
	Apply(context.Context, configpoc.Revision) error
	Current() string
}
type Observer func(context.Context) (string, []firewallipc.Counter, string, error)
type Session struct {
	run                    string
	namespace, last, epoch uint64
	recovering             bool
	applied                string
	engine                 Engine
	guardian               *nftguardian.Guardian
	observe                Observer
	compile                firewallipc.Compiler
	localObserve           func(context.Context) (string, localpolicy.Observation, error)
}

func validHex(value string, length int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == length && hex.EncodeToString(decoded) == value
}
func zeroRevision(r configpoc.Revision) bool {
	return r.Hash == "" && r.Config.SchemaVersion == 0 && r.Config.DefaultAction == "" && len(r.Config.Rules) == 0 && r.Config.LocalServices == nil
}
func validRevision(r configpoc.Revision) bool {
	a, err := firewallnft.Compile(r.Config)
	return err == nil && a.Revision.Hash == r.Hash
}
func ValidMessage(m firewallipc.Message) bool {
	return validMessage(m, validRevision)
}
func validMessage(m firewallipc.Message, revisionOK func(configpoc.Revision) bool) bool {
	switch m.Verb {
	case "bootstrap", "apply":
		return revisionOK(m.Revision) && zeroRevision(m.Previous) && m.Hash == "" && m.Lease == "" && m.TTL == 0
	case "arm":
		return revisionOK(m.Revision) && revisionOK(m.Previous) && helperLease.MatchString(m.Lease) && m.Hash == "" && m.TTL >= 500*time.Millisecond && m.TTL <= 120*time.Second
	case "confirm":
		return zeroRevision(m.Revision) && zeroRevision(m.Previous) && helperLease.MatchString(m.Lease) && validHex(m.Hash, 32) && m.TTL == 0
	case "state", "observe", "recovered":
		return zeroRevision(m.Revision) && zeroRevision(m.Previous) && m.Hash == "" && m.Lease == "" && m.TTL == 0
	default:
		return false
	}
}

// handle binds a new API epoch to boot/resume recovery before accepting leases.
// Protocol violations close the channel; valid rejected operations get a bounded reply.
func (s *Session) handle(ctx context.Context, m firewallipc.Message) (firewallipc.Reply, error) {
	epoch := m.Sequence >> 32
	ordinal := m.Sequence & 0xffffffff
	if m.Run != s.run || epoch == 0 || ordinal == 0 || m.Sequence <= s.last || !validMessage(m, s.validRevision) {
		return firewallipc.Reply{}, errHelper
	}
	if epoch != s.epoch {
		if epoch <= s.epoch || ordinal != 1 {
			return firewallipc.Reply{}, errHelper
		}
		s.epoch = epoch
		s.recovering = true
		s.applied = ""
	} else if m.Sequence != s.last+1 {
		return firewallipc.Reply{}, errHelper
	}
	s.last = m.Sequence
	reply := firewallipc.Reply{Run: s.run, Sequence: m.Sequence, Namespace: s.namespace}
	if m.Verb == "bootstrap" || m.Verb == "apply" || m.Verb == "arm" {
		reply.Artifact, _ = s.digest(m.Revision.Config)
	}
	var err error
	switch m.Verb {
	case "bootstrap":
		if !s.recovering {
			err = errHelper
		} else {
			err = s.guardian.Bootstrap(ctx, m.Revision)
		}
		if err == nil {
			s.applied = m.Revision.Hash
		}
	case "apply":
		state := s.guardian.Status()
		// A no-op pending transition still needs its old lease cleared on API
		// restart. Both trusted revisions and effective readback must coincide.
		if s.recovering && (state.Phase == "armed" || state.Phase == "pending") && state.Previous == state.Target && state.Previous == m.Revision.Hash && s.engine.Current() == m.Revision.Hash {
			err = s.guardian.RecoverPrevious()
		}
		if err == nil {
			err = s.guardian.Apply(ctx, m.Revision)
		}
		if err == nil && s.recovering {
			s.applied = m.Revision.Hash
		}
	case "arm":
		if s.recovering {
			err = errHelper
		} else {
			state := s.guardian.Status()
			if state.Phase == "expired" {
				if m.Previous.Hash != state.Previous || s.engine.Current() != state.Previous {
					err = errHelper
				} else {
					err = s.guardian.RecoverPrevious()
				}
			}
			if err == nil {
				err = s.guardian.Arm(m.Lease, m.Previous, m.Revision, m.TTL)
			}
		}
	case "confirm":
		if s.recovering {
			err = errHelper
		} else {
			err = s.guardian.Confirm(m.Lease, m.Hash)
		}
	case "recovered":
		state := s.guardian.Status()
		if !s.recovering || s.applied == "" || s.engine.Current() != s.applied || (state.Phase != "idle" && state.Phase != "expired") {
			err = errHelper
		} else if state.Phase == "expired" {
			err = s.guardian.RecoverPrevious()
		}
		if err == nil {
			s.recovering = false
		}
	case "observe":
		if s.localObserve != nil {
			var observed localpolicy.Observation
			reply.Hash, observed, err = s.localObserve(ctx)
			if err == nil {
				reply.Local = &observed
			}
		} else {
			reply.Hash, reply.Counters, reply.CounterEpoch, err = s.observe(ctx)
		}
		if err == nil && (reply.Hash == "" || s.engine.Current() != reply.Hash) {
			err = errHelper
		}
	case "state":
	}
	state := s.guardian.Status()
	reply.State = firewalladmin.LeaseState{Phase: state.Phase, ID: state.ID, Previous: state.Previous, Target: state.Target, Deadline: state.Deadline}
	if err != nil {
		reply.Error = errHelper.Error()
		reply.Hash = ""
		reply.Counters = nil
		reply.CounterEpoch = ""
		reply.Local = nil
	}
	return reply, nil
}

func (s *Session) digest(c configpoc.Config) (string, error) {
	if s.compile != nil {
		return s.compile(c)
	}
	a, err := firewallnft.Compile(c)
	return a.Digest, err
}
func (s *Session) validRevision(r configpoc.Revision) bool {
	canonical, err := configpoc.Canonical(r.Config)
	if err != nil || canonical.Hash != r.Hash {
		return false
	}
	_, err = s.digest(r.Config)
	return err == nil
}

// NewLocalSession pins the Local-In compiler and actual observation collector
// once at startup; requests cannot select another domain or compiler.
func NewLocalSession(run string, namespace uint64, engine Engine, guardian *nftguardian.Guardian, compile firewallipc.Compiler, observe func(context.Context) (string, localpolicy.Observation, error)) (*Session, error) {
	if !ValidRun(run) || namespace == 0 || engine == nil || guardian == nil || compile == nil || observe == nil {
		return nil, errHelper
	}
	return &Session{run: run, namespace: namespace, engine: engine, guardian: guardian, compile: compile, localObserve: observe}, nil
}

func NewSession(run string, namespace uint64, engine Engine, guardian *nftguardian.Guardian, observe Observer) *Session {
	return &Session{run: run, namespace: namespace, engine: engine, guardian: guardian, observe: observe}
}
func (s *Session) Handle(ctx context.Context, m firewallipc.Message) (firewallipc.Reply, error) {
	return s.handle(ctx, m)
}
func (s *Session) Position() (uint64, uint64) { return s.last, s.epoch }
func ValidRun(value string) bool              { return validHex(value, 16) }
