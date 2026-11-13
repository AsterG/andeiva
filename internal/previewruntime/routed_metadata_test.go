package previewruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

func routedMetadataFixture() Metadata {
	return Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 11, GatewayNamespace: 22}
}

func TestRoutedMetadataV2ProfilesAndLegacyBytes(t *testing.T) {
	legacy := routedMetadataFixture()
	legacy.SchemaVersion = 1
	legacy.SourceNamespace = 33
	legacy.SinkNamespace = 44
	raw, err := json.Marshal(legacy)
	const golden = `{"schema_version":1,"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","boot_id":"12345678-1234-1234-1234-123456789abc","host_namespace":11,"gateway_namespace":22,"source_namespace":33,"sink_namespace":44}`
	if err != nil || string(raw) != golden || legacy.Validate() != nil || legacy.ValidateRouted() != nil {
		t.Fatal("legacy metadata contract changed", err)
	}
	appliance := routedMetadataFixture()
	if appliance.ValidateRouted() != nil || appliance.Validate() == nil {
		t.Fatal("new profile crossed legacy boundary")
	}
	raw, err = json.Marshal(appliance)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"schema_version":2,"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","boot_id":"12345678-1234-1234-1234-123456789abc","host_namespace":11,"gateway_namespace":22,"source_namespace":0,"sink_namespace":0}`
	if string(raw) != expected {
		t.Fatal("two-namespace profile has fabricated identities")
	}
	var decoded Metadata
	if firewallipc.Decode(raw, &decoded) != nil || decoded != appliance || decoded.ValidateRouted() != nil {
		t.Fatal("strict profile round trip")
	}
	// Missing fixture identities never opt a schema-1 declaration into schema 2.
	legacy.SourceNamespace = 0
	legacy.SinkNamespace = 0
	if legacy.Validate() == nil || legacy.ValidateRouted() == nil {
		t.Fatal("implicit profile promotion")
	}
}

func TestRoutedMetadataV2RejectsMixedOrUnknownProfiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Metadata)
	}{
		{"zero-version", func(m *Metadata) { m.SchemaVersion = 0 }},
		{"unknown-version", func(m *Metadata) { m.SchemaVersion = 3 }},
		{"negative-version", func(m *Metadata) { m.SchemaVersion = -1 }},
		{"source-present", func(m *Metadata) { m.SourceNamespace = 33 }},
		{"sink-present", func(m *Metadata) { m.SinkNamespace = 44 }},
		{"source-alias", func(m *Metadata) { m.SourceNamespace = m.HostNamespace }},
		{"host-zero", func(m *Metadata) { m.HostNamespace = 0 }},
		{"gateway-zero", func(m *Metadata) { m.GatewayNamespace = 0 }},
		{"host-is-gateway", func(m *Metadata) { m.GatewayNamespace = m.HostNamespace }},
		{"run-empty", func(m *Metadata) { m.RunID = "" }},
		{"run-upper", func(m *Metadata) { m.RunID = strings.Repeat("A", 32) }},
		{"run-length", func(m *Metadata) { m.RunID = strings.Repeat("a", 34) }},
		{"run-nonhex", func(m *Metadata) { m.RunID = strings.Repeat("x", 32) }},
		{"boot-empty", func(m *Metadata) { m.BootID = "" }},
		{"boot-zero", func(m *Metadata) { m.BootID = "00000000-0000-0000-0000-000000000000" }},
		{"boot-upper", func(m *Metadata) { m.BootID = strings.ToUpper(m.BootID) }},
		{"boot-suffix", func(m *Metadata) { m.BootID += "\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := routedMetadataFixture()
			tc.change(&m)
			if m.ValidateRouted() == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}

	raw, err := json.Marshal(routedMetadataFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"schema_version":1`, `"SchemaVersion":2`, `"profile":"trusted"`} {
		payload := string(raw[:len(raw)-1]) + "," + extra + "}"
		var m Metadata
		if firewallipc.Decode([]byte(payload), &m) == nil {
			t.Fatal("non-strict bootstrap metadata accepted")
		}
	}

}

func BenchmarkRoutedMetadataV2Validation(b *testing.B) {
	m := routedMetadataFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := m.ValidateRouted(); err != nil {
			b.Fatal(err)
		}
	}
}
