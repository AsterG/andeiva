package previewruntime

// RoutedMetadataSchemaVersion identifies an explicitly provisioned host and
// gateway pair. Source and sink namespaces belong only to the legacy fixture.
const RoutedMetadataSchemaVersion = 2

// ValidateRouted checks a declared profile, not namespace provenance. Routed
// assembly must still match the supervisor's pinned descriptors and identities.
// Legacy consumers deliberately continue using Validate and reject schema 2.
func (m Metadata) ValidateRouted() error {
	switch m.SchemaVersion {
	case 1:
		return m.Validate()
	case RoutedMetadataSchemaVersion:
		if !validHex(m.RunID, 16) || !bootPattern.MatchString(m.BootID) || m.BootID == "00000000-0000-0000-0000-000000000000" || m.HostNamespace == 0 || m.GatewayNamespace == 0 || m.HostNamespace == m.GatewayNamespace || m.SourceNamespace != 0 || m.SinkNamespace != 0 {
			return ErrConfiguration
		}
		return nil
	default:
		return ErrConfiguration
	}
}
