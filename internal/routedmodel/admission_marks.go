package routedmodel

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
)

const admissionMarkPrefix uint32 = 0xae000000
const MaxAdmissionMarks uint32 = 0x00ffffff

var ErrAdmissionMarksExhausted = errors.New("ANDEIVA_ROUTED_ADMISSION_MARKS_EXHAUSTED")
var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type AdmissionMark struct {
	Rule string `json:"rule"`
	Mark uint32 `json:"mark"`
}

// AdmissionMarks is part of the selected operation proof. Issued includes
// every serial reserved for this boot, even if its operation was interrupted
// before any effects. The single writer advances it before the helper applies.
type AdmissionMarks struct {
	Boot     string          `json:"boot"`
	Revision string          `json:"revision"`
	Issued   uint32          `json:"issued"`
	Bindings []AdmissionMark `json:"bindings"`
}

// MarkIndex verifies completeness and canonical order against the policy.
// The caller must authenticate the boot ID and selected immutable receipt.
func (m AdmissionMarks) MarkIndex(revision Revision) (map[string]uint32, error) {
	policy, err := Canonical(revision.Policy)
	if err != nil || policy.Hash != revision.Hash || m.Revision != revision.Hash ||
		!bootIDPattern.MatchString(m.Boot) || m.Issued > MaxAdmissionMarks {
		return nil, ErrPolicy
	}
	marks := make(map[string]uint32, len(policy.Policy.Rules))
	seen := make(map[uint32]bool, len(policy.Policy.Rules))
	index := 0
	for _, rule := range policy.Policy.Rules {
		if !rule.IsEnabled() || rule.Action != "allow" {
			continue
		}
		if index >= len(m.Bindings) {
			return nil, ErrPolicy
		}
		binding := m.Bindings[index]
		serial := binding.Mark & MaxAdmissionMarks
		if binding.Rule != rule.ID || seen[binding.Mark] || binding.Mark&^MaxAdmissionMarks != admissionMarkPrefix ||
			serial == 0 || serial > m.Issued {
			return nil, ErrPolicy
		}
		marks[rule.ID] = binding.Mark
		seen[binding.Mark] = true
		index++
	}
	if index != len(m.Bindings) {
		return nil, ErrPolicy
	}
	return marks, nil
}

// ReserveAdmissionMarks derives the next binding from the last selected policy
// and a trusted boot high-water mark. prior can be nil only on adoption with a
// verified closed gateway. Persist the returned high-water mark before effects.
// needsClosure indicates a change to the effective coverage of an otherwise
// identical rule. Its entire old mark is retired on the guarded path.
func ReserveAdmissionMarks(boot string, highWater uint32, prior *AdmissionMarks, before, target Revision) (next AdmissionMarks, needsClosure bool, err error) {
	policy, err := Canonical(target.Policy)
	if err != nil || policy.Hash != target.Hash || !bootIDPattern.MatchString(boot) || highWater > MaxAdmissionMarks {
		return AdmissionMarks{}, false, ErrPolicy
	}
	oldMarks := map[string]uint32{}
	oldIndexes := map[string]int{}
	if prior != nil {
		oldMarks, err = prior.MarkIndex(before)
		if err != nil || boot != prior.Boot || highWater < prior.Issued {
			return AdmissionMarks{}, false, ErrPolicy
		}
		// A different route or NAT context has no unchanged rule scope,
		// even if the filters' text is identical.
		if before.Policy.Network.Hash != policy.Policy.Network.Hash || !slices.Equal(before.Policy.NAT, policy.Policy.NAT) {
			needsClosure = true
			clear(oldMarks)
		} else {
			for i, rule := range before.Policy.Rules {
				oldIndexes[rule.ID] = i
			}
		}
	}
	next = AdmissionMarks{Boot: boot, Revision: target.Hash, Issued: highWater, Bindings: []AdmissionMark{}}
	for i, rule := range policy.Policy.Rules {
		if !rule.IsEnabled() || rule.Action != "allow" {
			continue
		}
		mark := oldMarks[rule.ID]
		if mark != 0 {
			oldIndex := oldIndexes[rule.ID]
			previous := before.Policy.Rules[oldIndex]
			// Both rules are enabled. Ignore their distinct bool pointers.
			previous.Enabled = rule.Enabled
			switch {
			case previous != rule:
				mark = 0
			case !samePrecedingCoverage(before.Policy.Rules[:oldIndex], policy.Policy.Rules[:i], rule):
				needsClosure = true
				mark = 0
			}
		}
		if mark == 0 {
			if next.Issued == MaxAdmissionMarks {
				return AdmissionMarks{}, false, ErrAdmissionMarksExhausted
			}
			next.Issued++
			mark = admissionMarkPrefix | next.Issued
		}
		next.Bindings = append(next.Bindings, AdmissionMark{Rule: rule.ID, Mark: mark})
	}
	return next, needsClosure, nil
}

func samePrecedingCoverage(before, target []Rule, rule Rule) bool {
	// Equal sets of earlier intersecting predicates imply equal coverage
	// for this rule regardless of their order or verdict. A changed predicate
	// may be redundant, but the guarded path handles that conservatively.
	scopes := func(rules []Rule) map[Rule]struct{} {
		result := make(map[Rule]struct{})
		source, destination := netip.MustParsePrefix(rule.Source), netip.MustParsePrefix(rule.Destination)
		for _, earlier := range rules {
			if !earlier.IsEnabled() || earlier.Path != rule.Path || earlier.Protocol != rule.Protocol ||
				!portsOverlap(earlier.SourcePorts, rule.SourcePorts) || !portsOverlap(earlier.DestinationPorts, rule.DestinationPorts) ||
				!source.Overlaps(netip.MustParsePrefix(earlier.Source)) || !destination.Overlaps(netip.MustParsePrefix(earlier.Destination)) {
				continue
			}
			earlier.ID, earlier.Action, earlier.Enabled = "", "", nil
			result[earlier] = struct{}{}
		}
		return result
	}
	old, next := scopes(before), scopes(target)
	if len(old) != len(next) {
		return false
	}
	for scope := range old {
		if _, exists := next[scope]; !exists {
			return false
		}
	}
	return true
}

func portsOverlap(a, b Ports) bool {
	return a.From <= b.To && b.From <= a.To
}

// VerifyAdmissionChange rejects any alternate allocation, including an old
// mark supplied for a restored rule. highWater is the boot watermark selected
// before this reservation, including interrupted allocations.
func VerifyAdmissionChange(previous, assigned AdmissionMarks, highWater uint32, before, target Revision) error {
	next, _, err := ReserveAdmissionMarks(previous.Boot, highWater, &previous, before, target)
	if err != nil {
		return err
	}
	if next.Boot != assigned.Boot || next.Revision != assigned.Revision || next.Issued != assigned.Issued ||
		!slices.Equal(next.Bindings, assigned.Bindings) {
		return ErrPolicy
	}
	return nil
}
