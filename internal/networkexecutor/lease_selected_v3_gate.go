package networkexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
)

// RecoverClosedSelectedV3 accepts only caller-authenticated selected ownership.
// It validates the complete existing table, then removes both sets. It never
// adopts a live token, resets its timeout, or makes the old sequence reusable.
func (g *LeaseGate) RecoverClosedSelectedV3(ctx context.Context, snapshot LeaseSelectedSnapshotV3) error {
	if g == nil {
		return ErrScope
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, err := CanonicalLeaseSelectedSnapshotV3(snapshot)
	if err != nil || g.ready(ctx) != nil || g.initialized || s.Fact().Owner != g.opts.Owner || s.Desired.Hash != g.opts.Desired.Hash || s.WAN != g.wan.Binding || g.closedForwarding() != nil {
		return ErrScope
	}
	b, err := g.kernel.Observe(ctx)
	if err != nil || leaseGateRecoveryReadV3(b, s.WAN.Name) != nil {
		g.fenced = true
		return ErrLeaseGateUncertain
	}
	g.initialized = true
	g.seen = s.Sequence
	if err = g.closeUnder(ctx); err != nil {
		return err
	}
	return nil
}

func leaseGateRecoveryReadV3(b []byte, wan string) error {
	if len(b) == 0 || len(b) > leaseGateMaxJSON {
		return ErrObservation
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var root struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if d.Decode(&root) != nil {
		return ErrObservation
	}
	enabled, token := false, false
	digest := ""
	var ttl int64
	for _, o := range root.Objects {
		raw, ok := o["set"]
		if !ok {
			continue
		}
		var set struct {
			Name     string            `json:"name"`
			Elements []json.RawMessage `json:"elem"`
		}
		if json.Unmarshal(raw, &set) != nil || len(set.Elements) > 1 {
			return ErrObservation
		}
		if set.Name == "enabled" {
			enabled = len(set.Elements) == 1
		}
		if set.Name == "live" && len(set.Elements) == 1 {
			token = true
			var value struct {
				Element struct {
					Comment string `json:"comment"`
					Timeout int64  `json:"timeout"`
				} `json:"elem"`
			}
			if json.Unmarshal(set.Elements[0], &value) != nil || !leaseGateHex(value.Element.Comment, 64) || value.Element.Timeout <= 0 || value.Element.Timeout > 604800 {
				return ErrObservation
			}
			digest, ttl = value.Element.Comment, value.Element.Timeout
		}
	}
	_, err := leaseGateRead(b, wan, enabled, token, digest, ttl)
	return err
}

func (g *LeaseGate) VerifyClosedSelectedV3(ctx context.Context) error {
	if g == nil {
		return ErrScope
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ready(ctx) != nil || !g.initialized || g.opened || g.closedForwarding() != nil {
		return ErrLeaseGate
	}
	_, err := g.read(ctx, false, false)
	return err
}

// VerifySelectedStateV3 compares actual kernel state with the retained original
// LAN baseline. Expired authority permits baseline proof, never target proof.
func (l *LeaseExecutor) VerifySelectedStateV3(ctx context.Context, snapshot LeaseSelectedSnapshotV3, state LeaseSelectedStateV3) error {
	if l == nil || l.base == nil {
		return ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := CanonicalLeaseSelectedSnapshotV3(snapshot)
	if err != nil || l.base.identity == nil || s.Identity != *l.base.identity || s.Desired.Hash != l.desired.Hash || s.Fact().Owner != l.owner || !reflect.DeepEqual(observation{Links: s.Links, Routes: s.Routes}, l.baseline) || l.base.ready(ctx) != nil || l.guard(ctx) != nil {
		return ErrScope
	}
	first, err := l.base.observe(ctx)
	if err != nil {
		return err
	}
	second, err := l.base.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return ErrObservation
	}
	switch state {
	case LeaseSelectedBaselineV3:
		if !reflect.DeepEqual(first, l.baseline) {
			return ErrObservation
		}
	case LeaseSelectedTargetV3:
		if l.base.active == nil || l.fact != s.Fact() || !l.matches(first, l.base.active.revision, true) {
			return ErrObservation
		}
		return l.sameFact(ctx, s.Fact())
	default:
		return ErrScope
	}
	return nil
}
