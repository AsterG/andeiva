package configpoc

import "reflect"

func (s *v2Store) preservesPublishedFeaturesV2(next v2State) bool {
	if retainedDHCPColdAuditFollowsV1(s.state.RoutedDHCP, next.RoutedDHCP) && !validatesRetainedDHCPColdAuditEdgeV1(s.state, next, s.selector.Current, s.readObject) {
		return false
	}
	if reflect.DeepEqual(s.state.RoutedDHCPConfiguration, next.RoutedDHCPConfiguration) {
		return preservesFeaturesV2(s.state, next)
	}
	if s.reserves == nil || !preservesSelectedDHCPConfigurationReadV4(s.state, next, s.selector.Current, s.selection, s.readObject, routedDHCPConfigurationHeaderV4) {
		return false
	}
	// The logical edge is insufficient on the write path. Validate the
	// selected physical bundles against the prospective state as well.
	return s.reserves.verifySelected(&v2Store{state: next, objectReader: s.readObject}) == nil
}

func preservesSelectedDHCPConfigurationReadV4(previous, next v2State, sourceHash string, sourceSelection v2Selection, load func(string, any) error, headerOf routedDHCPConfigurationHeaderOfV4) bool {
	return preservesRoutedDHCPConfigurationReadV4(previous, headerOf(previous), next, headerOf(next), actualDHCPConfigurationSourceV4(sourceHash, sourceSelection, previous), load, func(subject, id string) (v2Operation, error) {
		return (&v2Store{state: next, objectReader: load}).lookupRetained(subject, id)
	}, headerOf)
}

func validateRoutedDHCPConfigurationSelectionV4(h *v4RoutedDHCPConfigurationState, st v2State, load func(string, any) error, lookup func(string, string) (v2Operation, error), headerOf routedDHCPConfigurationHeaderOfV4) error {
	if h == nil {
		return validateRoutedDHCPSelectedV3(st, load)
	}
	_, err := routedDHCPConfigurationViewV4Read(h, st, load, lookup, headerOf)
	return err
}

// Only the current edge is materialized on demand. The caller's historical
// summary retains two hashes, not all prior state/configuration objects.
func (r *v2ReachabilityReader) preservesFeaturesConfigurationReadV4(previous, nextSummary v2State, sourceSelection v2Selection, sourceHash string, nextSelection v2Selection, headerOf routedDHCPConfigurationHeaderOfV4) (bool, error) {
	p, n := headerOf(previous), headerOf(nextSummary)
	coldAudit := retainedDHCPColdAuditFollowsV1(previous.RoutedDHCP, nextSummary.RoutedDHCP)
	if reflect.DeepEqual(p, n) && !coldAudit {
		return preservesFeaturesV2(previous, nextSummary), nil
	}
	var next v2State
	release, err := r.load(nextSelection.State, &next)
	if err != nil {
		return false, err
	}
	defer release()
	if next.Lineage != previous.Lineage || next.Generation != nextSummary.Generation || !reflect.DeepEqual(headerOf(next), n) {
		return false, ErrRecovery
	}
	if coldAudit {
		return preservesFeaturesV2(previous, next) && validatesRetainedDHCPColdAuditEdgeV1(previous, next, sourceHash, r.object), nil
	}
	ok := preservesRoutedDHCPConfigurationReadV4(previous, p, next, n, actualDHCPConfigurationSourceV4(sourceHash, sourceSelection, previous), r.object, func(subject, id string) (v2Operation, error) { return r.lookup(next, subject, id) }, headerOf)
	return ok, nil
}

func actualDHCPConfigurationSourceV4(hash string, selection v2Selection, st v2State) SelectionReferenceV2 {
	if st.RoutedDHCP == nil {
		return SelectionReferenceV2{}
	}
	return SelectionReferenceV2{Selection: hash, Previous: selection.Previous, State: selection.State, Lineage: selection.Lineage, Sequence: selection.Sequence, Generation: st.Generation, WorkHash: st.RoutedDHCP.Work, Mode: "dhcp-configuration-v4"}
}
