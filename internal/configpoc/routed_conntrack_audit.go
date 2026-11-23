package configpoc

const routedConntrackAuditFeatureV1 = "configuration.routed-conntrack-audit.v1"
const routedConntrackRetirementLimitV1 = 128

// RoutedConntrackCleanupV1 is provided only by the helper result already
// authenticated against the selected operation and exact kernel readback.
// The public operation body never supplies it.
type RoutedConntrackCleanupV1 struct {
	Operation string
	Retired   uint16
	Partial   bool
}

type routedConntrackCleanupV1 struct {
	Retired uint16 `json:"retired"`
	Partial bool   `json:"partial"`
}

func validRoutedConntrackAuditV1(a v2CoordinatorAudit) bool {
	if a.Cleanup == nil {
		return true
	}
	if a.Cleanup.Retired > routedConntrackRetirementLimitV1 || a.Lease == "" || a.OriginCommit == "" {
		return false
	}
	switch a.Kind {
	case OpCommit, OpRollback:
		return a.Result == "applied_pending_confirmation" && a.OriginCommit == a.Operation
	case "timeout", "restart":
		return a.Result == "reverted" && a.Subject == "system" && a.OriginCommit != a.Operation
	default:
		return false
	}
}
