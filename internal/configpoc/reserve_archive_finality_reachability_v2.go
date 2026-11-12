package configpoc

// FinalWork owns typed audit and recovery edges even after the ordinary
// catalogue no longer contains the originating operation.
func (r *v2ReachabilityReader) reserveArchiveFinality(archive v2ReserveArchive, key string, state v2State, depth int) error {
	var facts v2ReserveFinality
	if err := r.object(archive.FinalWork, &facts); err != nil {
		return err
	}
	if facts.Kind == "system" {
		return r.recoveryWithOrigin(facts.Origin.Object, facts.Origin.ID, key, state, depth, nil)
	}
	var origin v2Operation
	if err := r.object(facts.Origin.Object, &origin); err != nil {
		return err
	}
	if err := r.operationAudit(origin, state, depth); err != nil {
		return err
	}
	if err := r.reserveBundle(origin.Reserve, key, state, depth); err != nil {
		return err
	}
	if facts.Child != nil {
		var child v2Operation
		if err := r.object(facts.Child.Object, &child); err != nil {
			return err
		}
		if err := r.operationAudit(child, state, depth); err != nil {
			return err
		}
		if err := r.reserveBundle(child.Reserve, key, state, depth); err != nil {
			return err
		}
	}
	if facts.Recovery != nil {
		return r.recoveryWithOrigin(facts.Recovery.Object, facts.Recovery.ID, key, state, depth, &origin)
	}
	return nil
}
