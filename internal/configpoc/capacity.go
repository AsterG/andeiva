package configpoc

const (
	maxReceipts = 1024
	// A transition writes intent and outcome. Keep one such recovery available
	// after a pending transaction resolves; this is not unlimited restart space.
	recoveryRecords = 2
	pendingRecords  = 2 + recoveryRecords
)

func (s *Service) ordinaryReserve() int {
	if s.state.Snapshot.Pending != nil {
		return pendingRecords
	}
	return recoveryRecords
}

// requestCapacity is evaluated after authorization, exact replay and generation
// checks. It only admits capacity: operation-specific validation must still pass
// before any authority call or engine mutation. capacity(n) budgets n+1 records,
// each at the existing maximum size, including future receipts and audit fields.
func (s *Service) requestCapacity(request Request) bool {
	recordReserve, receiptReserve := 4, 1
	if s.state.Snapshot.Pending != nil {
		receiptReserve = 2 // owner confirmation and one explicit recovery
	}
	switch {
	case (request.Operation == OpCommit || request.Operation == OpRollback) && request.ConfirmFor > 0:
		recordReserve, receiptReserve = 1+pendingRecords, 2
	case request.Operation == OpConfirm:
		recordReserve, receiptReserve = recoveryRecords, 1
	case request.Operation == OpRecover && s.state.Snapshot.RecoveryRequired:
		recordReserve, receiptReserve = recoveryRecords-1, 0
	}
	return len(s.state.Receipts)+1+receiptReserve <= maxReceipts && s.store.capacity(recordReserve)
}
