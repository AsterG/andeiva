//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestWithLegacySnapshotV3RetainsLockAndDetachesSnapshot(t *testing.T) {
	area, path := checkpointFixtureArea(t)
	enabled := true
	initial := Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{{ID: "retained", Action: "allow", Enabled: &enabled, Match: &Match{Protocol: "tcp", Source: "198.18.0.1/32", Destination: "198.18.0.2/32", SourcePorts: PortRange{From: 1, To: 65535}, DestinationPorts: PortRange{From: 443, To: 443}}}}}
	// The engine is modeled only to construct a journal fixture.
	core, err := Open(path, []Engine{NewSimEngine("snapshot-fixture-only")}, Options{Initial: &initial})
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Close(); err != nil {
		t.Fatal(err)
	}
	expected, err := InspectLegacyV2(area, "firewall")
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = WithLegacySnapshotV3(context.Background(), area, "firewall", func(_ context.Context, fp LegacyFingerprintV2, snapshot Snapshot) error {
		if fp != expected || snapshot.Running.Hash == "" || len(snapshot.Running.Config.Rules) != 1 {
			return errors.New("wrong snapshot")
		}
		if lock, e := lockLegacyV2(area); e == nil {
			_ = lock.Close()
			return errors.New("source lock released")
		}
		hash = snapshot.Running.Hash
		snapshot.Running.Config.Rules[0].ID = "caller-mutation"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = WithLegacySnapshotV3(context.Background(), area, "firewall", func(_ context.Context, fp LegacyFingerprintV2, snapshot Snapshot) error {
		if fp != expected || snapshot.Running.Hash != hash || snapshot.Running.Config.Rules[0].ID != "retained" {
			return errors.New("caller changed source")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("callback")
	if err = WithLegacySnapshotV3(context.Background(), area, "firewall", func(context.Context, LegacyFingerprintV2, Snapshot) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = WithLegacySnapshotV3(ctx, area, "firewall", func(context.Context, LegacyFingerprintV2, Snapshot) error { t.Fatal("called after cancel"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = WithLegacySnapshotV3(context.Background(), area, "firewall", func(context.Context, LegacyFingerprintV2, Snapshot) error {
		return os.WriteFile(path+"/00000001.json", []byte("{}"), 0600)
	}); err == nil {
		t.Fatal("corruption accepted")
	}
}
