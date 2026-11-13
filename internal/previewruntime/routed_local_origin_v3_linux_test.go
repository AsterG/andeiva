//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func localOriginFixtureV3() *RoutedLocalOriginV3 {
	return &RoutedLocalOriginV3{Version: 1, Kind: "new-inactive-v1", CreatedAt: time.Unix(1700000000, 123).UTC(), Source: configpoc.LegacyFingerprintV2{Domain: "local_services", Source: strings.Repeat("a", 64), Tip: strings.Repeat("b", 64), Sequence: 1, Projection: 1, ReceiptIndex: strings.Repeat("c", 64)}, Revision: strings.Repeat("d", 64)}
}
func TestRoutedLocalOriginV3ExactFactsAndDetachedBootstrap(t *testing.T) {
	origin := localOriginFixtureV3()
	proof := configpoc.MigrationProvenanceV3{Sources: [2]configpoc.LegacyFingerprintV2{{Domain: "firewall"}, origin.Source}, LocalInitializedAt: origin.CreatedAt, LocalRevision: configpoc.Revision{Hash: origin.Revision}}
	if matchRoutedLocalOriginV3(origin, proof) != nil {
		t.Fatal("matching selected facts refused")
	}
	for _, change := range []func(*configpoc.MigrationProvenanceV3){
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].Domain = "firewall" },
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].Source = strings.Repeat("e", 64) },
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].Tip = strings.Repeat("e", 64) },
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].Sequence++ },
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].Projection++ },
		func(p *configpoc.MigrationProvenanceV3) { p.Sources[1].ReceiptIndex = strings.Repeat("e", 64) },
		func(p *configpoc.MigrationProvenanceV3) {
			p.LocalInitializedAt = p.LocalInitializedAt.Add(time.Nanosecond)
		},
		func(p *configpoc.MigrationProvenanceV3) { p.LocalRevision.Hash = strings.Repeat("e", 64) },
	} {
		changed := proof
		change(&changed)
		if matchRoutedLocalOriginV3(origin, changed) == nil {
			t.Fatal("substituted selected provenance accepted")
		}
	}
	if validateRoutedLocalOriginV3(nil) == nil {
		t.Fatal("missing origin accepted")
	}
	changed := *origin
	changed.Kind = "legacy"
	if validateRoutedLocalOriginV3(&changed) == nil {
		t.Fatal("invented legacy label accepted")
	}
	supervisor := &RoutedLaunchSupervisorV3{resources: RoutedLaunchResourcesV3{LocalOrigin: cloneRoutedLocalOriginV3(origin)}}
	origin.Source.Tip = strings.Repeat("f", 64)
	bootstrap := supervisor.bootstrap(0, 0)
	if bootstrap.LocalOrigin == nil || bootstrap.LocalOrigin.Source.Tip == origin.Source.Tip {
		t.Fatal("caller alias changed captured provenance")
	}
	bootstrap.LocalOrigin.Source.Tip = strings.Repeat("e", 64)
	if next := supervisor.bootstrap(0, 0); next.LocalOrigin.Source.Tip == bootstrap.LocalOrigin.Source.Tip {
		t.Fatal("bootstrap mutated supervisor provenance")
	}
	frame, err := json.Marshal(bootstrap)
	if err != nil || len(frame) > routedLaunchFrameV3 {
		t.Fatal("origin exceeded existing bootstrap bound", err)
	}
	supervisor.resources.LocalOrigin = nil
	frame, err = json.Marshal(supervisor.bootstrap(0, 0))
	if err != nil || strings.Contains(string(frame), "local_origin") {
		t.Fatal("legacy nil origin changed encoded fields", err)
	}
}

func TestRoutedLocalOriginV3MatchesActualSelectedMigrationWithoutEffects(t *testing.T) {
	// Real store/reserve/G1/IPC with explicitly simulated kernel/network engines.
	fixture := newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionActionAuthorityV2)
	actual, err := fixture.fullReader.MigrationProvenanceV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := &RoutedLocalOriginV3{Version: 1, Kind: "new-inactive-v1", CreatedAt: actual.LocalInitializedAt, Source: actual.Sources[1], Revision: actual.LocalRevision.Hash}
	before, err := fixture.service.Current(fixture.binding, "routed")
	if err != nil {
		t.Fatal(err)
	}
	batches := len(fixture.kernel.batches)
	if err = verifySelectedRoutedLocalOriginV3(context.Background(), fixture.fullReader, expected); err != nil {
		t.Fatal(err)
	}
	changed := *expected
	changed.CreatedAt = changed.CreatedAt.Add(time.Nanosecond)
	if verifySelectedRoutedLocalOriginV3(context.Background(), fixture.fullReader, &changed) == nil {
		t.Fatal("mismatching creation event accepted")
	}
	after, err := fixture.service.Current(fixture.binding, "routed")
	if err != nil || before.Global != after.Global || len(fixture.kernel.batches) != batches {
		t.Fatal("provenance check changed selected state or kernel", err)
	}
}
