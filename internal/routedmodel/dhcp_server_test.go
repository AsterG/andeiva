package routedmodel_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

func server() *dhcpserver.Config {
	return &dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{ID: "office", InterfaceID: "lan", Subnet: "198.18.0.0/24", Router: "198.18.0.1", Pools: []dhcpserver.Pool{{First: "198.18.0.10", Last: "198.18.0.20"}}, LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000}}}
}

func TestDHCPServerPolicyVersionsAndLegacyBytes(t *testing.T) {
	input := routednft.LabPolicy()
	old, err := routedmodel.Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	// Frozen pre-extension wire shape and field order; no omitted/new field.
	legacy := struct {
		SchemaVersion         int                      `json:"schema_version"`
		LabOnly               bool                     `json:"lab_only"`
		RequireIdentification bool                     `json:"require_identification"`
		RequireInspection     bool                     `json:"require_inspection"`
		Network               networkplan.Revision     `json:"network"`
		Rules                 []routedmodel.Rule       `json:"rules"`
		NAT                   []routedmodel.Masquerade `json:"nat"`
	}{old.Policy.SchemaVersion, old.Policy.LabOnly, old.Policy.RequireIdentification, old.Policy.RequireInspection, old.Policy.Network, old.Policy.Rules, old.Policy.NAT}
	want, _ := json.Marshal(legacy)
	got, _ := json.Marshal(old.Policy)
	digest := sha256.Sum256(want)
	if string(want) != string(got) || old.Hash != hex.EncodeToString(digest[:]) {
		t.Fatal("legacy bytes/hash changed")
	}
	input.DHCPServer = server()
	if _, err = routedmodel.Canonical(input); err == nil {
		t.Fatal("v1 accepted new field")
	}
	input.SchemaVersion = 2
	revision, err := routedmodel.Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	input.DHCPServer.Scopes[0].Pools[0].First = "changed"
	if revision.Policy.DHCPServer.Scopes[0].Pools[0].First != "198.18.0.10" {
		t.Fatal("aliased server")
	}
	input.DHCPServer = nil
	if _, err = routedmodel.Canonical(input); err == nil {
		t.Fatal("v2 omitted server")
	}
}

func TestDHCPServerDerivesOnlySelectedLAN(t *testing.T) {
	for _, role := range []networkplan.Role{networkplan.WAN, networkplan.Management, networkplan.LAN} {
		p := routednft.LabPolicy()
		p.SchemaVersion = 2
		p.DHCPServer = server()
		if role == networkplan.WAN {
			p.DHCPServer.Scopes[0].InterfaceID = "wan"
		}
		if role == networkplan.Management {
			p.DHCPServer.Scopes[0].InterfaceID = "management"
		}
		if role == networkplan.LAN {
			p.DHCPServer.Scopes[0].Router = "198.18.0.2"
		}
		if _, err := routedmodel.Canonical(p); err == nil {
			t.Fatal("foreign LAN binding accepted", role)
		}
	}
	p := routednft.LabPolicy()
	p.SchemaVersion = 2
	p.DHCPServer = server()
	p.DHCPServer.Enabled = false
	r, err := routedmodel.Canonical(p)
	if err != nil || r.Policy.DHCPServer.Enabled || len(r.Policy.DHCPServer.Scopes) != 1 {
		t.Fatal("disabled state lost", err)
	}
}
