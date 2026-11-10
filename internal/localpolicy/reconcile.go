package localpolicy

import (
	"fmt"
	"slices"
)

// Listener observations must come from a trusted, namespace-scoped collector.
// This package does not collect them or verify process ownership itself.
type Listener struct {
	Owner        string   `json:"owner"`
	Service      string   `json:"service"`
	Interface    string   `json:"interface"`
	LocalAddress string   `json:"local_address"`
	Protocol     Protocol `json:"protocol"`
	Port         uint16   `json:"port"`
}

type Observation struct {
	Revision  string          `json:"revision"`
	Listeners []Listener      `json:"listeners"`
	Rules     []EffectiveRule `json:"rules"`
}

type Difference struct {
	Code    string `json:"code"`
	Subject string `json:"subject"`
}

type Reconciliation struct {
	Consistent  bool         `json:"consistent"`
	Differences []Difference `json:"differences"`
}

const maxListeners = 4096

// Reconcile compares supplied observations to declarations. Consistent means
// equality of these inputs, not a kernel, authentication or connectivity proof.
// The future coordinator must never confirm solely from this result.
func Reconcile(c Config, o Observation) (Reconciliation, error) {
	a, err := Compile(c)
	if err != nil {
		return Reconciliation{}, err
	}
	if len(o.Listeners) > maxListeners || len(o.Rules) > MaxRules {
		return Reconciliation{}, invalid("observation_capacity")
	}
	r := Reconciliation{Differences: []Difference{}}
	add := func(code, subject string) { r.Differences = append(r.Differences, Difference{code, subject}) }
	if o.Revision != a.Revision.Hash {
		add("revision_mismatch", "")
	}
	expected := map[Listener]bool{}
	for _, s := range a.Revision.Config.Services {
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			for _, e := range s.Endpoints {
				for port := e.FirstPort; ; port++ {
					l := Listener{s.Owner, s.ID, b.Interface, b.LocalAddress, e.Protocol, port}
					expected[l] = true
					if port == e.LastPort {
						break
					}
				}
			}
		}
	}
	seen := map[Listener]bool{}
	for _, l := range o.Listeners {
		if seen[l] {
			add("duplicate_listener", listenerKey(l))
		}
		seen[l] = true
		if !expected[l] {
			add("unexpected_listener", listenerKey(l))
		}
	}
	for l := range expected {
		if !seen[l] {
			add("missing_listener", listenerKey(l))
		}
	}
	expectedRules := map[string]EffectiveRule{}
	seenRules := map[string]bool{}
	for _, rule := range a.Rules {
		expectedRules[rule.ID] = rule
	}
	for _, rule := range o.Rules {
		if seenRules[rule.ID] {
			add("duplicate_rule", rule.ID)
		}
		seenRules[rule.ID] = true
		want, ok := expectedRules[rule.ID]
		if !ok {
			add("unexpected_rule", rule.ID)
		} else if rule != want {
			add("rule_mismatch", rule.ID)
		}
	}
	for id := range expectedRules {
		if !seenRules[id] {
			add("missing_rule", id)
		}
	}
	slices.SortFunc(r.Differences, func(a, b Difference) int {
		if a.Code < b.Code {
			return -1
		}
		if a.Code > b.Code {
			return 1
		}
		if a.Subject < b.Subject {
			return -1
		}
		if a.Subject > b.Subject {
			return 1
		}
		return 0
	})
	r.Consistent = len(r.Differences) == 0
	return r, nil
}

func listenerKey(l Listener) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%d", l.Owner, l.Service, l.Interface, l.LocalAddress, l.Protocol, l.Port)
}
