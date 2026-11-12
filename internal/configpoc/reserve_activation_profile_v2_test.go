//go:build linux

package configpoc

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestV2ReserveActivationRefusesLargeLegacyStateWithoutMutation(t *testing.T) {
	s, _, _, subject := v2Fixture(t, v2MaximumOperations)
	defer s.close()
	state := clone(s.state)
	for i := len(state.Namespaces); i < int(state.NamespaceSlots); i++ {
		state.Namespaces = append(state.Namespaces, v2Namespace{ID: fmt.Sprintf("legacy-%d-%s", i, strings.Repeat("a", 90)), Subject: subject, Domain: "firewall", AdmitUntil: state.Clock.Add(time.Hour), Closed: true, Open: []string{}})
		state.NamespaceSequence++
	}
	for i := len(state.Subjects); i < int(state.SubjectSlots); i++ {
		state.Subjects = append(state.Subjects, v2Subject{ID: fmt.Sprintf("legacy-%d-%s", i, strings.Repeat("s", 100)), Login: fmt.Sprintf("legacy-%d-%s", i, strings.Repeat("u", 100)), CredentialRevision: checkpointDigest([]byte(fmt.Sprint(i))), Retired: true})
		state.SubjectSequence++
	}
	if err := s.publish(state); err != nil {
		t.Fatal(err)
	}
	projected := clone(s.state)
	projected.RecoveryReserveVersion = 1
	if reserveMetadataStateFitsV2(projected) {
		t.Fatal("fixture must exceed new profile")
	}
	before := clone(s.state)
	selected := s.selector
	used := s.used
	if err := s.enableClosingCreditsLocked(); err != errV2Limited {
		t.Fatalf("activation was not rejected cleanly: %v", err)
	}
	if s.blocked || s.state.RecoveryReserveVersion != 0 || s.selector != selected || s.used != used || !reserveJSONEqualV2(s.state, before) {
		t.Fatal("rejected activation mutated legacy authority")
	}
}
