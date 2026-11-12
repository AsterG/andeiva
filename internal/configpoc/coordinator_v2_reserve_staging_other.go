//go:build !linux

package configpoc

func recoverReservePendingV2(*v2Store, *v2ReserveManager) error { return ErrRecovery }
