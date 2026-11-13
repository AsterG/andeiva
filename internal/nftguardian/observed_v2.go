package nftguardian

// SnapshotObserved is a read-only, atomic view of authority metadata and engine
// identity. It does not reconcile expiry: the independent timer owns that work.
func (g *Guardian) SnapshotObserved() (State, string, error) {
	if g == nil {
		return State{}, "", ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.observedLocked()
}

func (g *Guardian) observedLocked() (State, string, error) {
	if g.closed || g.engine == nil {
		return State{}, "", ErrLease
	}
	return g.snapshotLocked(g.engine.Current(), false)
}

// MatchObserved compares every scope field under the same guardian lock as the
// effective readback. A stale witness cannot clear a timer or initialize state.
func (g *Guardian) MatchObserved(expected State, hash string) error {
	if g == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, current, err := g.observedLocked()
	if err != nil || s.Phase != expected.Phase || s.ID != expected.ID || s.Previous != expected.Previous || s.Target != expected.Target || !s.Deadline.Equal(expected.Deadline) || current != hash {
		return ErrLease
	}
	return nil
}
