package configpoc

import "strings"

func validateRoutedActiveV2(state v2State, load func(string, any) error) error {
	active := state.RoutedActive
	if active == nil {
		return nil
	}
	if state.Configuration == nil || !hasFeatureV2(state, v2RoutedFeature) || active.Side != "before" && active.Side != "target" {
		return errV2Unavailable
	}
	plan, err := loadRoutedWorkV2(active.Work, state.Lineage, load)
	if err != nil {
		return err
	}
	if plan.work.Kind == v2BootKind && !hasFeatureV2(state, v2RoutedBootFeature) {
		return errV2Unavailable
	}
	if err = routedBootHistoryV2(plan, state, load); err != nil {
		return err
	}
	expected := *state.Configuration
	if expected.Pending != nil {
		var previous v2Configuration
		if load(expected.Pending.Previous, &previous) != nil || !validV2Configuration(&previous) {
			return errV2Unavailable
		}
		expected = previous
	}
	bundle := plan.previous
	if active.Side == "target" {
		bundle = plan.target
	}
	if bundle.Composite.Hash != expected.Running.Hash {
		return errV2Unavailable
	}
	root, hash := expected.VerifiedIndex, expected.Running.Hash
	for depth := 0; root != "" && depth <= v2VerifiedDepthLimit; depth++ {
		var node v2VerifiedNode
		if load(root, &node) != nil || !validVerifiedNodeV2(node, depth, hash[:depth]) {
			return errV2Unavailable
		}
		if node.Kind == "branch" {
			root = node.Children[strings.IndexByte("0123456789abcdef", hash[depth])]
			continue
		}
		for _, entry := range node.Entries {
			if entry.Revision != hash {
				continue
			}
			var audit v2CoordinatorAudit
			if load(entry.Audit, &audit) != nil || audit.Format != v2Format || audit.Operation != entry.Operation || audit.Running != hash || audit.Sequence > state.Configuration.AuditSequence || audit.Generation > state.Generation || audit.Result != "verified" && audit.Result != "applied" {
				return errV2Unavailable
			}
			return nil
		}
		return errV2Unavailable
	}
	return errV2Unavailable
}
