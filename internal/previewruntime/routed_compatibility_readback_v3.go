package previewruntime

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
)

type routedLegacyReadbackV3 interface {
	ObserveLegacy(context.Context) (firewallnft.Observation, bool, uint64, error)
}

// NewRoutedReadbackSessionV3 provides compatibility reads from the group-owned
// engine. It has no independent guardian, writable engine or mutation verbs.
// Its bootstrap state means verified legacy-table absence, not group readiness.
func NewRoutedReadbackSessionV3(run string, namespace uint64, authority *RoutedAuthority) (*SessionV2, error) {
	if !ValidRun(run) || namespace == 0 || authority == nil || authority.engine == nil || authority.identity.Namespace != namespace {
		return nil, errHelper
	}
	return &SessionV2{base: &Session{run: run, namespace: namespace}, domain: "firewall", readOnly: true, routedReadback: authority.engine, routedOwner: authority}, nil
}

func (s *SessionV2) handleRoutedReadbackV3(ctx context.Context, m firewallipc.RequestV2, p firewallipc.CommandV2) (firewallipc.ReplyV2, error) {
	reply := firewallipc.ReplyV2{ProtocolVersion: 2, Run: m.Run, Sequence: m.Sequence, Namespace: m.Namespace, Domain: m.Domain, Verb: m.Verb}
	fail := func() (firewallipc.ReplyV2, error) {
		reply.Error, reply.Payload = errHelper.Error(), json.RawMessage(`{}`)
		return reply, nil
	}
	if !s.readOnly || s.domain != "firewall" || ctx == nil || ctx.Err() != nil || (m.Verb != "state" && m.Verb != "observe" && m.Verb != "attach_observed") {
		return fail()
	}
	observation, present, generation, err := s.routedReadback.ObserveLegacy(ctx)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	result := firewallipc.ResultV2{State: firewalladmin.LeaseState{Phase: "bootstrap"}}
	if present {
		if !validRevision(observation.Revision) || observation.Revision.Config.SchemaVersion != 4 {
			return fail()
		}
		result.State.Phase, result.Hash = "idle", observation.Revision.Hash
	} else if !zeroRevision(observation.Revision) || len(observation.Rules) != 0 {
		return fail()
	}
	switch m.Verb {
	case "observe":
		if !present {
			return fail()
		}
		result.Counters = make([]firewallipc.Counter, 0, len(observation.Rules))
		for _, rule := range observation.Rules {
			result.Counters = append(result.Counters, firewallipc.Counter{ID: rule.ID, Packets: rule.Packets, Bytes: rule.Bytes})
		}
		result.CounterEpoch = s.base.run + "." + strconv.FormatUint(generation, 10)
	case "attach_observed":
		observed := firewallipc.ObservedScope{State: result.State, Hash: result.Hash}
		if p.Observed != observed {
			return fail()
		}
		s.attached, s.cold = true, !present
		result.ObservedScope = &observed
	}
	reply.Payload, err = json.Marshal(result)
	if err != nil {
		return firewallipc.ReplyV2{}, errHelper
	}
	return reply, nil
}
