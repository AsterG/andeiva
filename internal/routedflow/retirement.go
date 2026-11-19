package routedflow

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AsterG/andeiva/internal/routedmodel"
)

const MaxRetirements = 128
const RetirementTimeout = 2 * time.Second

type retirementRule struct {
	rule                routedmodel.Rule
	source, destination netip.Prefix
	mark                uint32
}

// Retirement is constructed by the gateway helper from its authenticated
// selected operation and complete policies. It does not accept addresses,
// marks or deletion keys from a management request.
type Retirement struct {
	operation      string
	gateway, host  uint64
	before, target []retirementRule
	used           atomic.Bool
}

type RetirementResult struct {
	Operation string
	Retired   int
}

func NewRetirement(operation string, gateway, host uint64, before, target routedmodel.Revision) (*Retirement, error) {
	if len(operation) == 0 || len(operation) > 128 || strings.IndexFunc(operation, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_')
	}) >= 0 || gateway == 0 || host == 0 || gateway == host {
		return nil, ErrObservation
	}
	prior, err := routedmodel.Canonical(before.Policy)
	if err != nil || prior.Hash != before.Hash {
		return nil, ErrObservation
	}
	next, err := routedmodel.Canonical(target.Policy)
	if err != nil || next.Hash != target.Hash || prior.Policy.Network.Hash != next.Policy.Network.Hash {
		return nil, ErrObservation
	}
	oldNAT, _ := json.Marshal(prior.Policy.NAT)
	newNAT, _ := json.Marshal(next.Policy.NAT)
	if string(oldNAT) != string(newNAT) {
		return nil, ErrObservation
	}

	p := &Retirement{operation: operation, gateway: gateway, host: host,
		before: retirementRules(prior.Policy.Rules), target: retirementRules(next.Policy.Rules)}
	previous := make(map[uint32]routedmodel.Rule, len(p.before))
	for _, old := range p.before {
		previous[old.mark] = old.rule
	}
	for _, updated := range p.target {
		if old, sameMark := previous[updated.mark]; sameMark {
			// Enabled pointers are distinct after canonicalization.
			l, _ := json.Marshal(old)
			r, _ := json.Marshal(updated.rule)
			if string(l) != string(r) {
				return nil, ErrObservation
			}
		}
	}
	return p, nil
}

func retirementRules(rules []routedmodel.Rule) []retirementRule {
	out := make([]retirementRule, 0, len(rules))
	for _, rule := range rules {
		if rule.IsEnabled() {
			out = append(out, retirementRule{rule: rule, source: netip.MustParsePrefix(rule.Source),
				destination: netip.MustParsePrefix(rule.Destination), mark: routedmodel.RuleMark(rule)})
		}
	}
	return out
}

func ruleWithMark(rules []retirementRule, mark uint32) (retirementRule, bool) {
	for _, rule := range rules {
		if rule.mark == mark && rule.rule.Action == "allow" {
			return rule, true
		}
	}
	return retirementRule{}, false
}

func allowsMarkedTuple(rules []retirementRule, path routedmodel.Path, tuple Tuple, mark uint32) bool {
	for _, r := range rules {
		if r.rule.Path != path || r.rule.Protocol != tuple.Protocol ||
			!r.source.Contains(tuple.Source.Address) || !r.destination.Contains(tuple.Destination.Address) ||
			tuple.Source.Port < r.rule.SourcePorts.From || tuple.Source.Port > r.rule.SourcePorts.To ||
			tuple.Destination.Port < r.rule.DestinationPorts.From || tuple.Destination.Port > r.rule.DestinationPorts.To {
			continue
		}
		return r.rule.Action == "allow" && r.mark == mark
	}
	return false
}

type retirementEntry struct {
	original Tuple
	zone     uint16
	id       uint32
}

func (p *Retirement) selectAffected(snapshot Snapshot) ([]retirementEntry, error) {
	if snapshot.SchemaVersion != 1 {
		return nil, ErrObservation
	}
	if len(snapshot.Flows) > MaxFlows {
		return nil, ErrLimit
	}
	var affected []retirementEntry
	for _, f := range snapshot.Flows {
		if f.Mark == nil || *f.Mark&0xff000000 != 0xad000000 {
			continue
		}
		mark := *f.Mark
		next, exists := ruleWithMark(p.target, mark)
		if exists && allowsMarkedTuple(p.target, next.rule.Path, f.Original, mark) {
			// Includes connections admitted since the atomic replacement.
			continue
		}
		prior, exists := ruleWithMark(p.before, mark)
		if !exists || !allowsMarkedTuple(p.before, prior.rule.Path, f.Original, mark) || f.ID == nil || *f.ID == 0 {
			return nil, ErrObservation
		}
		if len(affected) == MaxRetirements {
			return nil, ErrLimit
		}
		zone := zoneValue(f.Zone)
		if f.Original.Zone != nil {
			if f.Zone != nil && *f.Original.Zone != zone {
				return nil, ErrObservation
			}
			zone = *f.Original.Zone
		}
		affected = append(affected, retirementEntry{original: f.Original, zone: zone, id: *f.ID})
	}
	return affected, nil
}

func (p *Retirement) run(ctx context.Context, t transport, sequence, port uint32) (RetirementResult, error) {
	result := RetirementResult{Operation: p.operation}
	observed, err := collect(ctx, t, sequence, port)
	if err != nil {
		return result, err
	}
	affected, err := p.selectAffected(observed)
	if err != nil {
		return result, err
	}
	for _, entry := range affected {
		sequence++
		if err := retireEntry(ctx, t, sequence, port, entry); err != nil {
			return result, err
		}
		result.Retired++
	}
	rechecked, err := collect(ctx, t, sequence+1, port)
	if err != nil {
		return result, err
	}
	remaining, err := p.selectAffected(rechecked)
	if err != nil {
		return result, err
	}
	if len(remaining) != 0 {
		return result, ErrObservation
	}
	return result, ctx.Err()
}
