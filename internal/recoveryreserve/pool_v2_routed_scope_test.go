package recoveryreserve

import (
	"strings"
	"testing"
	"time"
)

func TestRoutedScopeV2DomainBinding(t *testing.T) {
	base := ScopeV2{Kind: "operation", Lineage: "lineage", Bundle: "bundle", Operation: "operation", Namespace: "namespace", Subject: "subject", Domain: "routed", Fingerprint: strings.Repeat("a", 64), Global: 1, Generation: 1, Origin: "origin", Lease: "lease", Deadline: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	routed, err := base.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"firewall", "local_services"} {
		other := base
		other.Domain = domain
		hash, err := other.Hash()
		if err != nil || hash == routed {
			t.Fatal("domain does not bind scope", domain, err)
		}
	}
	for _, domain := range []string{"", "network", "Routed", "routed/../firewall"} {
		other := base
		other.Domain = domain
		if other.Validate() == nil {
			t.Fatal("unsupported domain accepted", domain)
		}
	}
}
