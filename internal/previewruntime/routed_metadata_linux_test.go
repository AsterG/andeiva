//go:build linux

package previewruntime

import (
	"context"
	"testing"
)

func TestRoutedMetadataV2ReadinessKeepsTrustedIdentity(t *testing.T) {
	m, ids, options := helperFixtureV3(t)
	m.SchemaVersion = RoutedMetadataSchemaVersion
	m.SourceNamespace = 0
	m.SinkNamespace = 0
	if err := routedHelperReadinessV3(m, ids, options); err != nil {
		t.Fatal("two-namespace pinned readiness", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Metadata)
	}{
		{"run", func(m *Metadata) { m.RunID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }},
		{"boot", func(m *Metadata) { m.BootID = "22345678-1234-1234-1234-123456789abc" }},
		{"host", func(m *Metadata) { m.HostNamespace++ }},
		{"gateway", func(m *Metadata) { m.GatewayNamespace++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := m
			tc.change(&changed)
			if changed.ValidateRouted() != nil {
				t.Fatal("test must retain structural validity")
			}
			if routedHelperReadinessV3(changed, ids, options) == nil {
				t.Fatal("metadata substituted trusted authority identity")
			}
		})
	}
	if _, err := OpenRoutedHelperV3(context.Background(), m, ids, options); err == nil {
		t.Fatal("declared profile replaced actual helper credentials/namespace")
	}
}

func TestRoutedMetadataV2RejectsUnboundKernel(t *testing.T) {
	m := routedMetadataFixture()
	if _, err := newRoutedKernelV3(m); err == nil {
		t.Fatal("declared namespace replaced actual pinned execution context")
	}
	m.GatewayNamespace = m.HostNamespace
	if _, err := newRoutedKernelV3(m); err == nil {
		t.Fatal("host execution profile accepted")
	}
}
