package configpoc

import "github.com/AsterG/andeiva/internal/recoveryreserve"

type v2ReserveClaims struct {
	Admission recoveryreserve.SlotClaimV2 `json:"admission"`
	Plan      recoveryreserve.SlotClaimV2 `json:"plan"`
	Emergency recoveryreserve.SlotClaimV2 `json:"emergency"`
}

type v2ReserveBundle struct {
	Scope         recoveryreserve.ScopeV2    `json:"scope"`
	Claims        v2ReserveClaims            `json:"claims"`
	Admission     recoveryreserve.BindingV2  `json:"admission"`
	Plan          *recoveryreserve.BindingV2 `json:"plan,omitempty"`
	PlanScope     *recoveryreserve.ScopeV2   `json:"plan_scope,omitempty"`
	PlanIntent    *v2CoordinatorIntent       `json:"plan_intent,omitempty"`
	ClosingEscrow *v2ReserveClaims           `json:"closing_escrow,omitempty"`
}

type v2ActiveReserve struct {
	Work          string           `json:"work"`
	Bundle        *v2ReserveBundle `json:"bundle"`
	CanonicalHeld bool             `json:"canonical_held"`
}

type v2ReserveAdmission struct {
	Format        string                  `json:"format"`
	Version       uint8                   `json:"version"`
	Scope         recoveryreserve.ScopeV2 `json:"scope"`
	Claims        v2ReserveClaims         `json:"claims"`
	ClosingEscrow *v2ReserveClaims        `json:"closing_escrow,omitempty"`
}

type v2ReservePlan struct {
	Format    string                    `json:"format"`
	Version   uint8                     `json:"version"`
	Scope     recoveryreserve.ScopeV2   `json:"scope"`
	Admission recoveryreserve.BindingV2 `json:"admission"`
	Intent    v2CoordinatorIntent       `json:"intent"`
}

type v2ReserveEmergency struct {
	Format            string                    `json:"format"`
	Version           uint8                     `json:"version"`
	Scope             recoveryreserve.ScopeV2   `json:"scope"`
	Admission         recoveryreserve.BindingV2 `json:"admission"`
	Plan              recoveryreserve.BindingV2 `json:"plan"`
	Selection         string                    `json:"selection"`
	SelectionSequence uint64                    `json:"selection_sequence,string"`
	Intent            string                    `json:"intent"`
	Code              string                    `json:"code"`
}

func (claims v2ReserveClaims) all() []recoveryreserve.SlotClaimV2 {
	return []recoveryreserve.SlotClaimV2{claims.Admission, claims.Plan, claims.Emergency}
}

func reserveWorkV2(bundle *v2ReserveBundle) string {
	if bundle == nil {
		return ""
	}
	if bundle.Scope.Kind == "operation" {
		return bundle.Scope.Operation
	}
	return bundle.Scope.Recovery
}

func reserveActiveIndexV2(st *v2State, work string) int {
	for i, active := range st.ActiveReserves {
		if active.Work == work {
			return i
		}
	}
	return -1
}
