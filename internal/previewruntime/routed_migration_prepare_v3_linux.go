//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const RoutedMigrationPrepareRoleV3 = "--andeiva-routed-migration-prepare-v3"
const routedMigrationAuthorizationPathV3 = "/etc/andeiva-preview/grouped-migration-authorization.json"

// This root-only operational grant is separate from the immutable inspection
// draft. Bindings never come from account names or matching credentials.
type routedMigrationAuthorizationV3 struct {
	Version    int                         `json:"version"`
	PlanSHA256 string                      `json:"plan_sha256"`
	Bindings   []configpoc.LegacyBindingV2 `json:"bindings"`
}

type routedMigrationPreparedV3 struct {
	Version     int                      `json:"version"`
	PlanSHA256  string                   `json:"plan_sha256"`
	LocalOrigin RoutedLocalOriginV3      `json:"local_origin"`
	Profiles    [3]routedProfileRecordV3 `json:"profiles"`
	WriteBudget routedWriteBudgetV3      `json:"write_budget"`
}

func decodeMigrationAuthorizationV3(raw, draft []byte) (routedMigrationPlanV3, routedMigrationAuthorizationV3, error) {
	var p routedMigrationPlanV3
	var a routedMigrationAuthorizationV3
	digest := sha256.Sum256(draft)
	if len(draft) == 0 || len(draft) > 65536 || len(raw) == 0 || len(raw) > 65536 || !jsoncheck.UniqueControlFields(draft) || !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(draft, &p) != nil || firewallipc.Decode(raw, &a) != nil || p.Version != 1 || p.State != "draft" || len(p.Bindings) != 0 || a.Version != 1 || a.PlanSHA256 != hex.EncodeToString(digest[:]) || len(a.Bindings) > 256 {
		return p, a, ErrConfiguration
	}
	for _, b := range a.Bindings {
		if b.Source != p.Firewall.Source || b.Actor == "" || b.ReceiptIndex != p.Firewall.ReceiptIndex || b.Subject == "" {
			return p, a, ErrConfiguration
		}
		found := false
		for _, subject := range p.Subjects {
			if subject.ID == b.Subject && !subject.Retired {
				found = true
			}
		}
		if !found {
			return p, a, ErrConfiguration
		}
	}
	return p, a, nil
}

// The absence adapter never programs a kernel. Each Apply/Current requests a
// fresh privileged source readback through the fixed parent pipe.
type migrationAbsenceProxyV3 struct {
	ctx             context.Context
	verify          configpoc.OfflineMigrationReadbackV3
	expected        [2]configpoc.LegacyFingerprintV2
	firewall, local configpoc.Revision
}

func (p *migrationAbsenceProxyV3) Name() string { return "verified-inactive-source" }
func (p *migrationAbsenceProxyV3) Validate(c configpoc.Config) error {
	r, e := configpoc.Canonical(c)
	if e != nil || r.Hash != p.local.Hash {
		return ErrConfiguration
	}
	return nil
}
func (p *migrationAbsenceProxyV3) Apply(ctx context.Context, r configpoc.Revision) error {
	if p.Validate(r.Config) != nil || r.Hash != p.local.Hash {
		return ErrConfiguration
	}
	return p.verify.VerifyMigratedSources(ctx, p.expected, p.firewall, p.local)
}
func (p *migrationAbsenceProxyV3) Current() string {
	if p.ctx == nil || p.ctx.Err() != nil || p.verify.VerifyMigratedSources(p.ctx, p.expected, p.firewall, p.local) != nil {
		return ""
	}
	return p.local.Hash
}

// prepareMigrationRootsV3 writes only newly provisioned API-owned private roots.
// Conversion to the shared reader profile and activation are separate steps.
func prepareMigrationRootsV3(ctx context.Context, roots [6]*os.Root, p routedMigrationPlanV3, a routedMigrationAuthorizationV3, accounts []adminauth.Account, accountDigest string, verify configpoc.OfflineMigrationReadbackV3, budget configpoc.BudgetV2) (out routedMigrationPreparedV3, result error) {
	if ctx == nil || ctx.Err() != nil || verify == nil || budget.Bytes == 0 || budget.Inodes == 0 || validateMigrationPlanV3(p, accounts, accountDigest, p.Firewall) != nil || a.Version != 1 || !validHex(a.PlanSHA256, 32) {
		return out, ErrConfiguration
	}
	for _, root := range roots {
		if root == nil {
			return out, ErrConfiguration
		}
	}
	// roots: original FW, new local source, destination, admission, plan, emergency.
	var expected [2]configpoc.LegacyFingerprintV2
	expected[0] = p.Firewall
	var initialized time.Time
	var local configpoc.Revision
	err := configpoc.WithLegacySnapshotV3(ctx, roots[0], "firewall", func(ctx context.Context, fp configpoc.LegacyFingerprintV2, s configpoc.Snapshot) error {
		if fp != p.Firewall || s.Running.Hash != s.Startup.Hash || s.Running.Hash != s.LastGood.Hash {
			return configpoc.ErrConflict
		}
		var e error
		local, e = configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}})
		if e != nil {
			return e
		}
		absence := &migrationAbsenceProxyV3{ctx: ctx, verify: verify, expected: [2]configpoc.LegacyFingerprintV2{fp, {Domain: "local_services"}}, firewall: s.Running, local: local}
		local, initialized, e = configpoc.PrepareInactiveLocalSourceV3(ctx, roots[1], absence)
		return e
	})
	if err != nil {
		return out, err
	}
	expected[1], err = configpoc.InspectLegacyV2(roots[1], "local_services")
	if err != nil {
		return out, err
	}
	out = routedMigrationPreparedV3{WriteBudget: routedWriteBudgetV3{Bytes: budget.Bytes, Inodes: budget.Inodes}, Version: 1, PlanSHA256: a.PlanSHA256, LocalOrigin: RoutedLocalOriginV3{Version: 1, Kind: "new-inactive-v1", CreatedAt: initialized, Source: expected[1], Revision: local.Hash}}
	if validateRoutedLocalOriginV3(&out.LocalOrigin) != nil {
		return routedMigrationPreparedV3{}, ErrConfiguration
	}
	var pools [3]*recoveryreserve.PoolV2
	defer func() {
		for _, pool := range pools {
			if pool != nil {
				if e := pool.Close(); e != nil && result == nil {
					result = e
				}
			}
		}
		if result != nil {
			out = routedMigrationPreparedV3{}
		}
	}()
	poolRoots := [3]*os.Root{roots[3], roots[4], roots[5]}
	for i, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		pools[i], err = recoveryreserve.PrepareV2(poolRoots[i], 18, item.capacity, item.role)
		if err != nil {
			return out, err
		}
		profile, e := pools[i].Profile()
		if e != nil {
			return out, e
		}
		out.Profiles[i] = routedProfileRecordV3{ID: profile.ID, Role: profile.Role, Slots: profile.Slots, Capacity: profile.Capacity}
	}
	if err = configpoc.PrepareMigrationV2(roots[2], roots[0], roots[1], expected, p.Subjects, a.Bindings, budget, time.Now().UTC()); err != nil {
		return out, err
	}
	if err = configpoc.PrepareOfflineMigratedRoutedStoreV3(ctx, roots[2], [2]*os.Root{roots[0], roots[1]}, budget, configpoc.RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}, expected, verify, time.Now().UTC()); err != nil {
		return out, err
	}
	return out, nil
}

func validateMigrationPreparedV3(value routedMigrationPreparedV3, planSHA string) error {
	if value.Version != 1 || value.PlanSHA256 != planSHA || validateRoutedLocalOriginV3(&value.LocalOrigin) != nil || value.WriteBudget.Bytes != 1<<30 || value.WriteBudget.Inodes != 32768 {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for i, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		p := value.Profiles[i]
		if !validHex(p.ID, 16) || seen[p.ID] || p.Role != item.role || p.Slots != 18 || p.Capacity != item.capacity {
			return ErrConfiguration
		}
		seen[p.ID] = true
	}
	return nil
}
