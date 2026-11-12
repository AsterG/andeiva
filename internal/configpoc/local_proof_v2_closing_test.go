package configpoc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalProofV2UsesCanonicalClosingMembership(t *testing.T) {
	in, now := localProofFixtureV2(t, OpConfirm)
	in.Namespace.Open = []string{in.Operation.Request.Origin, "a", "b", "c", "d", "e", "f", "g"}
	in.closing = &localClosingMembershipV2{operation: in.Operation.ID, origin: in.Operation.Request.Origin, credit: "private-closing-credit", namespace: in.Operation.Namespace, subject: in.Operation.Subject, domain: in.Operation.Domain}
	if scope, err := ResolveLocalProofV2(in, now); err != nil || !scope.Valid() {
		t.Fatalf("reserved membership rejected: %v", err)
	}
	encoded, err := json.Marshal(in)
	if err != nil || strings.Contains(string(encoded), "private-closing-credit") {
		t.Fatal("internal closing relation leaked into JSON")
	}
	for _, field := range []string{"operation", "origin", "credit", "namespace", "subject", "domain", "duplicate-ordinary"} {
		t.Run(field, func(t *testing.T) {
			bad := in
			membership := *in.closing
			bad.closing = &membership
			switch field {
			case "operation":
				membership.operation = "foreign"
			case "origin":
				membership.origin = "foreign"
			case "credit":
				membership.credit = ""
			case "namespace":
				membership.namespace = "foreign"
			case "subject":
				membership.subject = "foreign"
			case "domain":
				membership.domain = "firewall"
			case "duplicate-ordinary":
				bad.Namespace.Open = []string{in.Operation.ID}
			}
			if _, err := ResolveLocalProofV2(bad, now); err == nil {
				t.Fatal("invalid closing membership produced a scope")
			}
		})
	}
}
