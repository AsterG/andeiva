package configpoc

// load is the caller's bounded, integrity-checking object reader. The previous
// snapshot is loaded once; neither forecast changes a selected configuration,
// executes an engine, or replaces current registry/other-domain declarations.
func reserveMetadataFutureFitsV2(state v2State, load func(string, any) error) error {
	if state.RecoveryReserveVersion == 0 {
		return nil
	}
	if state.RecoveryReserveVersion != 1 {
		return errV2Unavailable
	}
	if !reserveMetadataStateFitsV2(state) {
		return errV2Limited
	}
	if state.Configuration == nil || state.Configuration.Pending == nil {
		return nil
	}
	current := state.Configuration
	pending := current.Pending
	if load == nil || !validV2Configuration(current) || !validHash(pending.Previous) {
		return errV2Unavailable
	}
	var previous v2Configuration
	if err := load(pending.Previous, &previous); err != nil {
		return errV2Unavailable
	}
	_, hash, err := v2Canonical(previous)
	if err != nil || hash != pending.Previous || !validV2Configuration(&previous) || previous.Intent != nil || previous.Pending != nil {
		return errV2Unavailable
	}
	confirmed := clone(*current)
	own := domainSnapshotV2(&confirmed, pending.Domain)
	own.LastGood = own.Running
	if pending.Domain == "routed" {
		confirmed.LocalServices.LastGood = confirmed.LocalServices.Running
	}
	confirmed.Pending = nil
	confirmed.Intent = nil
	if err = confirmed.refresh(); err != nil {
		return errV2Unavailable
	}
	projected := state
	projected.Configuration = &confirmed
	if pending.Domain == "routed" {
		projected.RoutedActive = &v2RoutedActive{Work: pending.Target, Side: "target"}
	}
	if !reserveMetadataStateFitsV2(projected) {
		return errV2Limited
	}
	expired := clone(*current)
	own = domainSnapshotV2(&expired, pending.Domain)
	prior := domainSnapshotV2(&previous, pending.Domain)
	own.Running = prior.Running
	own.LastGood = prior.LastGood
	own.Candidate = nil
	if pending.Domain == "routed" {
		expired.LocalServices.Running = previous.LocalServices.Running
		expired.LocalServices.LastGood = previous.LocalServices.LastGood
		expired.LocalServices.Candidate = nil
		expired.CandidateGroup = nil
	}
	expired.Pending = nil
	expired.Intent = nil
	expired.RecoveryRequired = false
	if err = expired.refresh(); err != nil {
		return errV2Unavailable
	}
	projected.Configuration = &expired
	if pending.Domain == "routed" {
		projected.RoutedActive = &v2RoutedActive{Work: pending.Target, Side: "before"}
	}
	if !reserveMetadataStateFitsV2(projected) {
		return errV2Limited
	}
	return nil
}
