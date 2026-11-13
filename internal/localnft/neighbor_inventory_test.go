package localnft

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestNeighborInventoryExtractionPreservesBytesAndErrors(t *testing.T) {
	cfg := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"192.0.2.1", "fe80::1"}}}}
	links := []NeighborLink{{Interface: "lan0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"fe80::3", "fe80::2"}}}
	// The retained wrapper and shared pure contract must serialize identically.
	left, err := canonicalNeighbors(cfg, links)
	if err != nil {
		t.Fatal(err)
	}
	right, err := localpolicy.CanonicalNeighborInventory(cfg, links)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	if string(a) != string(b) {
		t.Fatal("canonical bytes changed")
	}
	if links[0].PeerAddresses[0] != "fe80::3" {
		t.Fatal("mutated caller inventory")
	}
	links[0].Interface = "foreign0"
	if _, err = canonicalNeighbors(cfg, links); !errors.Is(err, ErrPolicy) {
		t.Fatal("wrapper error identity changed", err)
	}
	if _, err = localpolicy.CanonicalNeighborInventory(cfg, links); !errors.Is(err, localpolicy.ErrNeighborInventory) {
		t.Fatal("shared error identity", err)
	}
}
