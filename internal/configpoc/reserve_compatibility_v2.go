package configpoc

func preservesRecoveryReserveV2(previous, next v2State) bool {
	return previous.RecoveryReserveVersion <= 1 && next.RecoveryReserveVersion <= 1 && next.RecoveryReserveVersion >= previous.RecoveryReserveVersion && (previous.ReserveArchiveRoot == "" || next.ReserveArchiveRoot != "")
}
