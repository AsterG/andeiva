package configpoc

const v1RoutedDHCPServerFeature = "configuration.routed-dhcp-server.v1"

// RoutedDHCPServerSupportV1 is implemented only by a trusted routed authority
// that includes DHCP server activation, effective readback, compensation and
// drainage in its transaction. It is not a request flag or a physical proof.
// Existing authorities do not opt in. Installing an engine is not sufficient.
type RoutedDHCPServerSupportV1 interface {
	RoutedAuthorityV1
	SupportsDHCPServerV1() bool
}

func configHasDHCPServerV1(config *Config) bool {
	return config != nil && config.Routed != nil && (config.Routed.SchemaVersion == 2 || config.Routed.DHCPServer != nil)
}

func configurationHasDHCPServerV1(cfg *v2Configuration) bool {
	if cfg == nil {
		return false
	}
	d := cfg.Firewall
	return configHasDHCPServerV1(&d.Running.Config) || configHasDHCPServerV1(&d.Startup.Config) || configHasDHCPServerV1(&d.LastGood.Config) || (d.Candidate != nil && configHasDHCPServerV1(&d.Candidate.Revision.Config))
}

func validDHCPServerFeatureV1(state v2State) bool {
	enabled := hasFeatureV2(state, v1RoutedDHCPServerFeature)
	return (!enabled || hasFeatureV2(state, v2RoutedFeature)) && (!configurationHasDHCPServerV1(state.Configuration) || enabled)
}
