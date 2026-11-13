package configpoc

func metadataOperationV2(kind string) bool {
	return kind == OpStage || kind == OpValidate || kind == OpSave || kind == OpReplaceCandidate || kind == OpDiscardCandidate
}

func domainSnapshotV2(state *v2Configuration, domain string) *v2DomainSnapshot {
	if domain == "local_services" {
		return &state.LocalServices
	}
	return &state.Firewall
}
func (c *v2Coordinator) enginesV2(domain string) []Engine {
	if domain == "local_services" {
		return c.local
	}
	return c.firewall
}
func effectDomainV2(previous, target v2Configuration) string {
	if previous.LocalServices.Running.Hash != target.LocalServices.Running.Hash {
		return "local_services"
	}
	if target.Pending != nil {
		return target.Pending.Domain
	}
	if previous.Pending != nil {
		return previous.Pending.Domain
	}
	return "firewall"
}
