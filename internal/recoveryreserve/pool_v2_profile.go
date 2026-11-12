package recoveryreserve

// ProfileV2 describes a pinned pool layout, not free capacity, bank integrity or
// authority to apply configuration. It is an internal assembly input, not a DTO.
type ProfileV2 struct {
	ID       string
	Role     RoleV2
	Slots    int
	Capacity int
}

func (p *PoolV2) Profile() (ProfileV2, error) {
	if p == nil {
		return ProfileV2{}, ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return ProfileV2{}, ErrUnavailable
	}
	return ProfileV2{ID: p.manifest.ID, Role: p.manifest.Role, Slots: p.manifest.Slots, Capacity: p.manifest.Capacity}, nil
}
