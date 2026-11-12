package configpoc

import "reflect"

func (m *v2ReserveManager) recoveryAllowance(s *v2Store, origin v2Operation) (func(), error) {
	previous := s.allowance
	restore := func() { s.allowance = previous }
	i := closingCreditIndexV2(&s.state, origin.ID)
	active := reserveActiveIndexV2(&s.state, origin.ID)
	if i < 0 || active < 0 || origin.Reserve == nil || origin.Reserve.ClosingEscrow == nil || !reflect.DeepEqual(s.state.ActiveReserves[active].Bundle, origin.Reserve) || m.verifyBundle(s, origin.Reserve) != nil {
		return nil, ErrRecovery
	}
	credit := s.state.ClosingCredits[i]
	if credit.Subject != origin.Subject || credit.Domain != origin.Domain || s.state.ReservedBytes < v2ClosingReserveBytes || s.state.ReservedInodes < v2ClosingReserveInodes {
		return nil, ErrRecovery
	}
	s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
	return restore, nil
}
