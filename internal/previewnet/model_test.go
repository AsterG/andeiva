package previewnet

import "testing"

func validMetadata() Metadata {
	return Metadata{SchemaVersion: 1, RunID: "0123456789abcdef0123456789abcdef", BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 1, GatewayNamespace: 2, SourceNamespace: 3, SinkNamespace: 4}
}

func TestMetadataRejectsAmbiguousNamespaceAndIdentity(t *testing.T) {
	m := validMetadata()
	if m.Validate() != nil {
		t.Fatal("valid metadata rejected")
	}
	for _, mutate := range []func(*Metadata){func(m *Metadata) { m.SchemaVersion = 2 }, func(m *Metadata) { m.RunID = "0123456789ABCDEF0123456789ABCDEF" }, func(m *Metadata) { m.RunID = "bad" }, func(m *Metadata) { m.BootID = "../boot" }, func(m *Metadata) { m.BootID = "12345678-1234-1234-1234-123456789ABc" }, func(m *Metadata) { m.GatewayNamespace = m.HostNamespace }, func(m *Metadata) { m.SourceNamespace = m.SinkNamespace }, func(m *Metadata) { m.SinkNamespace = 0 }} {
		m = validMetadata()
		mutate(&m)
		if m.Validate() == nil {
			t.Fatalf("accepted malformed metadata: %+v", m)
		}
	}
}

func TestControlHasNoConfigurationOrArbitraryEndpointOperations(t *testing.T) {
	for _, r := range []ControlRequest{{Operation: "status"}, {Operation: "probe", Protocol: "tcp", Port: 18080}, {Operation: "probe-reverse", Protocol: "udp", Port: 18082}} {
		if r.Validate() != nil {
			t.Fatal(r)
		}
	}
	for _, r := range []ControlRequest{{}, {Operation: "apply"}, {Operation: "status", Port: 22}, {Operation: "status", Protocol: "tcp"}, {Operation: "probe", Protocol: "TCP", Port: 18080}, {Operation: "probe", Protocol: "tcp", Port: 22}, {Operation: "probe", Protocol: "udp", Port: 18083}, {Operation: "probe", Protocol: "tcp;id", Port: 18080}} {
		if r.Validate() == nil {
			t.Fatal(r)
		}
	}
}
