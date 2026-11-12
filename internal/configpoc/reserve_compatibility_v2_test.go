package configpoc

import "testing"

func TestV2ReserveArchiveRootFrozenUntilTransactionResolved(t *testing.T) {
	for _, mode := range []string{"intent", "pending", "recovery", "idle"} {
		t.Run(mode, func(t *testing.T) {
			before := v2State{RecoveryReserveVersion: 1, ReserveArchiveRoot: "retained", Configuration: &v2Configuration{}}
			switch mode {
			case "intent":
				before.Configuration.Intent = &v2CoordinatorIntent{}
			case "pending":
				before.Configuration.Pending = &v2Confirmation{}
			case "recovery":
				before.Configuration.RecoveryRequired = true
			}
			after := clone(before)
			after.Configuration = &v2Configuration{}
			if !preservesRecoveryReserveV2(before, after) {
				t.Fatal("transaction cannot resolve while retaining root")
			}
			after.ReserveArchiveRoot = "replacement"
			want := mode == "idle"
			if preservesRecoveryReserveV2(before, after) != want {
				t.Fatal("unexpected archive-root mutation permission")
			}
			summary := v2State{RecoveryReserveVersion: before.RecoveryReserveVersion, ReserveArchiveRoot: before.ReserveArchiveRoot, Configuration: reserveFreezeSummaryV2(before.Configuration)}
			if preservesRecoveryReserveV2(summary, after) != want {
				t.Fatal("selection summary lost archive freeze")
			}
			after.ReserveArchiveRoot = ""
			if preservesRecoveryReserveV2(before, after) {
				t.Fatal("retained root removed")
			}
		})
	}
}
