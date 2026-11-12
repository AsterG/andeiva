package configpoc

// Admission never races past unresolved terminal maintenance. The complete
// lifecycle replaces this readiness gate only after exact archival proof.
func (m *v2ReserveManager) maintain(s *v2Store) error {
	if m == nil || s == nil {
		return ErrRecovery
	}
	return s.reserveMaintenanceReadyV2("")
}
