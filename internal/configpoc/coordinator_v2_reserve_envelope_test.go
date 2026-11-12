package configpoc

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// This deliberately overapproximates compatible optional fields. It proves
// serialization bounds only, not a physical allocation or valid runtime state.
func TestReserveEnvelopeMaximumDescriptors(t *testing.T) {
	id := strings.Repeat("x", 128)
	hash := strings.Repeat("f", 64)
	high := ^uint64(0)
	stamp := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	claims := v2ReserveClaims{}
	for _, item := range []struct {
		target *recoveryreserve.SlotClaimV2
		role   recoveryreserve.RoleV2
		pool   string
	}{{&claims.Admission, recoveryreserve.AdmissionV2, strings.Repeat("a", 32)}, {&claims.Plan, recoveryreserve.PlanV2, strings.Repeat("b", 32)}, {&claims.Emergency, recoveryreserve.EmergencyV2, strings.Repeat("c", 32)}} {
		*item.target = recoveryreserve.SlotClaimV2{Pool: item.pool, Slot: 17, Epoch: high, Owner: id, Role: item.role, ClaimSequence: high - 4, Capacity: 16384}
	}
	scope := recoveryreserve.ScopeV2{Kind: "operation", Lineage: id, Bundle: id, Operation: id, Namespace: id, Subject: id, Domain: "local_services", Fingerprint: hash, Global: high, Generation: high, Origin: id, Lease: id, Deadline: stamp}
	scopeHash, err := scope.Hash()
	if err != nil {
		t.Fatal(err)
	}
	binding := func(claim recoveryreserve.SlotClaimV2) recoveryreserve.BindingV2 {
		return recoveryreserve.BindingV2{Claim: claim, Sequence: high - 3, Digest: hash, Length: 16384, ScopeHash: scopeHash}
	}
	admission, plan := binding(claims.Admission), binding(claims.Plan)
	boot := v2BootID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	intent := v2CoordinatorIntent{Operation: id, Subject: id, Domain: "local_services", Kind: strings.Repeat("k", 128), Previous: hash, Target: hash, TargetGeneration: high, Recovery: false, OriginCommit: id, Lease: id, BootID: &boot}
	intent.GuardDeadline = &stamp // Deliberately incompatible fields overapproximate all optional bytes.
	intent.RoutedWork = hash
	pending := v2Confirmation{OriginCommit: id, Lease: id, Owner: id, Domain: "local_services", Previous: hash, Target: hash, Deadline: stamp}
	state := v2State{Configuration: &v2Configuration{Intent: &intent, Pending: &pending}}
	addFeatureV2(&state, v2GuardDeadlineFeature)
	for i := range 16 {
		bundle := &v2ReserveBundle{Scope: scope, Claims: claims, Admission: admission, Plan: &plan, PlanScope: &scope, PlanIntent: &intent}
		if i < 8 {
			bundle.ClosingEscrow = &claims
		}
		state.ActiveReserves = append(state.ActiveReserves, v2ActiveReserve{Work: id, Bundle: bundle})
	}
	state.SystemBundle = &v2ActiveReserve{Work: id, Bundle: &v2ReserveBundle{Scope: scope, Claims: claims, Admission: admission, Plan: &plan, PlanScope: &scope, PlanIntent: &intent}}
	common := v2Namespace{ID: id, Subject: id, Domain: "local_services", AdmitUntil: stamp}
	for range 8 {
		common.Open = append(common.Open, id)
		common.ClosingOpen = append(common.ClosingOpen, v2ClosingOpen{Operation: id, Origin: id, Credit: id})
	}
	state.Namespaces = append(state.Namespaces, common)
	for i := range 8 {
		state.ClosingCredits = append(state.ClosingCredits, v2ClosingCredit{ID: id, Origin: id, Subject: id, Domain: "local_services", Namespace: id, Child: id, ChildNamespace: id, ClosingNamespace: id})
		state.Namespaces = append(state.Namespaces, v2Namespace{ID: fmt.Sprint(i) + id[1:], Subject: id, Domain: "local_services", AdmitUntil: stamp, ClosingOrigin: id, ClosingOpen: []v2ClosingOpen{{Operation: id, Origin: id, Credit: id}}})
	}
	bound := reserveMetadataCoreV2(state)
	bound.ActiveReserves = state.ActiveReserves
	bound.SystemBundle = state.SystemBundle
	bound.ClosingCredits = state.ClosingCredits
	bound.Namespaces = state.Namespaces
	bound.Configuration.Intent = state.Configuration.Intent
	bound.Configuration.Pending = state.Configuration.Pending
	state = bound
	data, _, err := v2Canonical(state)
	if err != nil {
		t.Fatal(err)
	}
	core, _, err := v2Canonical(reserveMetadataCoreV2(state))
	if err != nil {
		t.Fatal(err)
	}
	extra := len(data) - len(core)
	if extra > 128*1024 {
		t.Fatalf("reserved envelope exceeds independently retained half: %d bytes", extra)
	}
	t.Logf("maximum overapproximated private descriptors: %d bytes; retained envelope: %d bytes", extra, 128*1024)
}
