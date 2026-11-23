//go:build linux

package configpoc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Physical authority is doubled as in the reboot scope tests. The selected
// files, reserves, archive and coordinator open are real; no power is cut.
type bootTerminalFixtureV4 struct {
	c         *v2Coordinator
	old       *boundaryAuthorityFixtureV2
	reader    *RoutedSelectionReaderV2
	subject   string
	operation string // interrupted operation, or the origin of a failed rollback
	recovery  string // failed rollback record, when the state has one
	startup   string
}

func interruptedRoutedFixtureV4(t *testing.T, state string) bootTerminalFixtureV4 {
	t.Helper()
	ctx := context.Background()
	c, old, principal, cfg := boundaryCoordinatorFixtureV2(t)
	reader := sharedBoundaryReaderV2(t, c, old)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
		t.Fatal(err)
	}
	f := bootTerminalFixtureV4{c: c, old: old, reader: reader, subject: principal.Subject}
	interruptAt := func(checkpoint string) {
		c.options.Hook = func(point string) error {
			if point == checkpoint {
				return ErrInterrupted
			}
			return nil
		}
	}
	seconds := uint64(90)
	commit := v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}
	switch state {
	case "commit":
		interruptAt("after_intent")
		op, _, err := routedRequestV2(t, c, principal, commit)
		if !errors.Is(err, ErrInterrupted) {
			t.Fatal("commit was not interrupted after its durable intent", err)
		}
		f.operation = op.ID
	case "rollback":
		origin, _, err := routedRequestV2(t, c, principal, commit)
		if err != nil {
			t.Fatal(err)
		}
		interruptAt("after_recovery_intent")
		if err = c.revertLocked(ctx, "timeout"); !errors.Is(err, ErrInterrupted) {
			t.Fatal("rollback was not interrupted after its durable intent", err)
		}
		f.operation, f.recovery = origin.ID, c.store.state.Configuration.Intent.Operation
	case "confirm":
		origin, result, err := routedRequestV2(t, c, principal, commit)
		if err != nil {
			t.Fatal(err)
		}
		interruptAt("after_intent")
		op, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: origin.ID, Target: result.Operation.Outcome.RunningRevision})
		if !errors.Is(err, ErrInterrupted) {
			t.Fatal("confirm was not interrupted after its durable intent", err)
		}
		f.operation = op.ID
	default:
		t.Fatal("unknown interrupted state")
	}
	c.options.Hook = nil
	selected := c.store.state.Configuration
	if selected.Intent == nil || selected.Intent.Kind == v2BootKind || !validHash(selected.Intent.RoutedWork) {
		t.Fatal("fixture did not leave a selected unfinished transaction")
	}
	f.startup = selected.Startup.Hash
	if selected.Running.Hash == f.startup && state != "commit" {
		t.Fatal("fixture must distinguish the unsaved Running from Startup")
	}
	return f
}

func (f bootTerminalFixtureV4) freshReader(t *testing.T, fresh *boundaryAuthorityFixtureV2) *RoutedSelectionReaderV2 {
	t.Helper()
	options := f.reader.options
	options.Identity = fresh.identity
	r, err := NewRoutedSelectionReaderV2(f.reader.area, options)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func auditCountV4(t *testing.T, c *v2Coordinator, operation string) (count int, results []string) {
	t.Helper()
	hash := c.store.state.Configuration.AuditTip
	for hash != "" {
		var audit v2CoordinatorAudit
		if err := c.store.readObject(hash, &audit); err != nil {
			t.Fatal(err)
		}
		if audit.Operation == operation {
			count++
			results = append(results, audit.Result)
		}
		hash = audit.Previous
	}
	return count, results
}

func (f bootTerminalFixtureV4) assertArchivedAndStartup(t *testing.T, opened *v2Coordinator, fresh *boundaryAuthorityFixtureV2) {
	t.Helper()
	st := opened.store.state
	cfg := st.Configuration
	if cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired || cfg.Running.Hash != f.startup || fresh.current != f.startup || st.RoutedBootBoundary != nil {
		t.Fatal("Startup was not selected and applied in the new scope")
	}
	// The only effect in the new scope is the Startup boot itself. No recovery
	// or rollback of the previous boot is replayed there or in the old scope.
	if fresh.recovers != 0 || fresh.bootstraps != 1 || f.old.recovers != 0 {
		t.Fatal("an effect of the previous boot was replayed", fresh.recovers, fresh.bootstraps, f.old.recovers)
	}
	op, err := opened.store.lookupRetained(f.subject, f.operation)
	if err != nil || op.State != "final" || op.Pinned || op.Outcome == nil {
		t.Fatal("original transaction is not terminal", err)
	}
	subject := f.operation
	want := "failed_rolled_back"
	if f.recovery != "" {
		var record v2RecoveryRecord
		entry, found, e := opened.verifiedLookup(cfg.RecoveryIndex, checkpointDigest([]byte(f.recovery)))
		if e != nil || !found || opened.store.readObject(entry.Audit, &record) != nil || record.ID != f.recovery || record.State != "final" || record.Pinned || record.Completed == nil {
			t.Fatal("failed rollback record is not terminal", e)
		}
		subject, want = f.recovery, "reverted"
	} else if op.Outcome.Code != want {
		t.Fatal("interrupted operation has an unexpected terminal result", op.Outcome.Code)
	}
	count, results := auditCountV4(t, opened, subject)
	if count != 1 || results[0] != want {
		t.Fatal("transaction was not archived exactly once in the protected audit", count, results)
	}
	if len(st.ActiveReserves) != 0 {
		t.Fatal("archived transaction still holds a reservation")
	}
	if n := attestationAuditCountV4(t, opened); n != 1 {
		t.Fatal("boot accepted without a drain receipt was not audited exactly once", n)
	}
	active, err := loadRoutedWorkV2(st.RoutedActive.Work, st.Lineage, opened.store.readObject)
	if err != nil || active.Scope().Identity != fresh.identity || active.RebootScopeEvidenceV4() == nil || !active.RebootScopeEvidenceV4().BootAttested || active.target.Composite.Hash != f.startup {
		t.Fatal("selected plan is not the attested Startup boot of the new scope", err)
	}
}

func TestRoutedBootTerminalV4ArchivesInterruptedTransactionAndSelectsStartup(t *testing.T) {
	for _, state := range []string{"commit", "rollback", "confirm"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			f := interruptedRoutedFixtureV4(t, state)
			fresh, proof := rebootAuthorityFixtureV4(t, f.c, f.old)
			bootAttestedFixtureV4(proof)
			// The helper captures its anchor before the coordinator publishes.
			r := f.freshReader(t, fresh)
			anchor, err := r.CaptureColdAnchorV1(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// While the Startup boot is selected, the helper must be able to
			// authorize its bootstrap from that anchor, as it does in the appliance.
			var during error
			resolved := false
			f.c.options.Hook = func(point string) error {
				if point == "after_boot_intent" {
					s := f.c.store
					resolved = true
					work := s.state.Configuration.Intent.RoutedWork
					plan, e := loadRoutedWorkV2(work, s.state.Lineage, s.readObject)
					if e != nil {
						during = e
						return nil
					}
					_, during = r.ResolveColdContinuationV1(ctx, anchor, plan.Reference(), SelectionBootstrapV2)
				}
				return nil
			}
			opened, err := reopenRebootHookFixtureV4(t, f.c, fresh, proof)
			if err != nil {
				t.Fatal("complete boot did not recover the interrupted transaction: ", err)
			}
			if !resolved || during != nil {
				t.Fatal("helper could not authorize the Startup bootstrap after the archive: ", resolved, during)
			}
			f.assertArchivedAndStartup(t, opened, fresh)
			// The complete selected history, including the attestation audit entry,
			// passes the independent full inspection of the helper reader.
			if _, err = r.PrepareCurrentView(ctx); err != nil {
				t.Fatal("full inspection refused the recovered store: ", err)
			}
			if proof.calls < 2 {
				t.Fatal("scope was not proved before the archive and again for Startup")
			}
			plan, err := loadRoutedWorkV2(opened.store.state.RoutedActive.Work, opened.store.state.Lineage, opened.store.readObject)
			if err != nil {
				t.Fatal(err)
			}
			// The independent helper reader accepts this exact continuation.
			if _, err = r.ResolveColdContinuationV1(ctx, anchor, plan.Reference(), SelectionResumeV2); err != nil {
				t.Fatal("helper continuation refused the archived predecessor: ", err)
			}
		})
	}
}

func TestRoutedBootTerminalV4KeepsRejectingTheSameBootAndMissingProof(t *testing.T) {
	for _, state := range []string{"commit", "rollback"} {
		for _, negative := range []string{"same boot", "no proof authority", "failed proof", "proof for another scope"} {
			t.Run(state+"/"+negative, func(t *testing.T) {
				f := interruptedRoutedFixtureV4(t, state)
				fresh, proof := rebootAuthorityFixtureV4(t, f.c, f.old)
				bootAttestedFixtureV4(proof)
				before, err := f.c.store.readRecordV2("selected.json", 4096)
				if err != nil {
					t.Fatal(err)
				}
				var opened *v2Coordinator
				switch negative {
				case "same boot":
					// A service restart: new run and namespace, same kernel boot.
					fresh.identity.BootID = f.old.identity.BootID
					opened, err = reopenRebootFixtureV4(t, f.c, fresh, proof)
				case "no proof authority":
					f.c.close()
					if err = f.c.store.close(); err != nil {
						t.Fatal(err)
					}
					s, e := openSharedStoreV2(f.c.store.root, f.c.store.budget, *f.c.store.access)
					if e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { _ = s.close() })
					opts := f.c.options
					opts.FreshScope, opts.RebootScope, opts.Routed, opts.RoutedIdentity, opts.Hook = nil, nil, fresh, fresh.identity, nil
					b := v2BootID(fresh.identity.BootID)
					opts.BootID = &b
					opened, err = openCoordinatorV2(context.Background(), s, f.c.firewall, f.c.local, opts)
				case "failed proof":
					previous := proof.mutate
					proof.mutate = func(p *RoutedRebootScopeEvidenceV4) { previous(p); p.ReceiptSHA256 = "unverified" }
					opened, err = reopenRebootFixtureV4(t, f.c, fresh, proof)
				case "proof for another scope":
					previous := proof.mutate
					proof.mutate = func(p *RoutedRebootScopeEvidenceV4) { previous(p); p.Old.RunID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }
					opened, err = reopenRebootFixtureV4(t, f.c, fresh, proof)
				}
				if err == nil {
					t.Fatal("unfinished transaction was accepted")
				}
				if opened != nil {
					opened.close()
				}
				after, e := f.c.store.readRecordV2("selected.json", 4096)
				if e != nil || string(before) != string(after) || fresh.applies != 0 || fresh.bootstraps != 0 || fresh.arms != 0 || fresh.recovers != 0 {
					t.Fatal("rejection changed the selection or caused effects", e)
				}
			})
		}
	}
}

// Power may be lost again at every publication of the recovery. Each further
// complete boot repeats it, and the original transaction stays archived once.
func TestRoutedBootTerminalV4RepeatsAfterInterruptionAtEveryPublication(t *testing.T) {
	points := []string{"before_boot_terminal_archive", "after_boot_terminal_archive", "before_boot_intent", "after_boot_intent", "after_boot_readback", "before_boot_completion", "after_boot_completion"}
	for _, state := range []string{"commit", "rollback"} {
		for _, point := range points {
			t.Run(state+"/"+point, func(t *testing.T) {
				f := interruptedRoutedFixtureV4(t, state)
				second, proof := rebootAuthorityFixtureV4(t, f.c, f.old)
				bootAttestedFixtureV4(proof)
				f.c.close()
				if err := f.c.store.close(); err != nil {
					t.Fatal(err)
				}
				s, err := openSharedStoreV2(f.c.store.root, f.c.store.budget, *f.c.store.access)
				if err != nil {
					t.Fatal(err)
				}
				opts := f.c.options
				opts.FreshScope, opts.RebootScope, opts.Routed, opts.RoutedIdentity = nil, proof, second, second.identity
				boot := v2BootID(second.identity.BootID)
				opts.BootID = &boot
				reached := false
				opts.Hook = func(name string) error {
					if name == point {
						reached = true
						return ErrInterrupted
					}
					return nil
				}
				interrupted, err := openCoordinatorV2(context.Background(), s, f.c.firewall, f.c.local, opts)
				if !reached || !errors.Is(err, ErrInterrupted) {
					t.Fatal("recovery was not interrupted at the publication step", reached, err)
				}
				if interrupted != nil {
					interrupted.close()
				}
				if err = s.close(); err != nil {
					t.Fatal(err)
				}
				// Third kernel boot. The interrupted second scope is the old one now
				// whenever its boot intent had already been selected.
				third := freshBoundaryAuthorityV2(f.old)
				third.identity.BootID, third.identity.RunID = "32345678-1234-1234-1234-123456789abc", "cccccccccccccccccccccccccccccccc"
				third.identity.Namespace, third.identity.Host = f.old.identity.Namespace, f.old.identity.Host
				final, err := openSharedStoreV2(f.c.store.root, f.c.store.budget, *f.c.store.access)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = final.close() })
				retired := f.old.identity
				if in := final.state.Configuration.Intent; point == "after_boot_completion" || in != nil && in.Kind == v2BootKind {
					retired = second.identity
				}
				again := &rebootScopeFixtureV4{proof: proof.proof}
				again.proof.Old, again.proof.New = retired, third.identity
				bootAttestedFixtureV4(again)
				opts.RebootScope, opts.Routed, opts.RoutedIdentity, opts.Hook = again, third, third.identity, nil
				boot = v2BootID(third.identity.BootID)
				opts.BootID = &boot
				opened, err := openCoordinatorV2(context.Background(), final, f.c.firewall, f.c.local, opts)
				if err != nil {
					t.Fatal("recovery could not be repeated on the next complete boot: ", err)
				}
				t.Cleanup(opened.close)
				cfg := opened.store.state.Configuration
				if cfg.Intent != nil || cfg.Pending != nil || cfg.Running.Hash != f.startup || third.current != f.startup || third.recovers != 0 || second.recovers != 0 {
					t.Fatal("repeated recovery did not select Startup without replaying effects")
				}
				wantAttestations := 1
				if point == "after_boot_completion" {
					wantAttestations++
				}
				if got := attestationAuditCountV4(t, opened); got != wantAttestations {
					t.Fatal("attestation was lost or duplicated across the next boot", got, wantAttestations)
				}
				subject, want := f.operation, "failed_rolled_back"
				if f.recovery != "" {
					subject, want = f.recovery, "reverted"
				}
				if count, results := auditCountV4(t, opened, subject); count != 1 || results[0] != want {
					t.Fatal("original transaction was not archived exactly once", count, results)
				}
				op, err := opened.store.lookupRetained(f.subject, f.operation)
				if err != nil || op.State != "final" || op.Pinned {
					t.Fatal("original transaction regained authority", err)
				}
			})
		}
	}
}

// Like reopenRebootFixtureV4, but keeps the coordinator hook so a test can
// observe the selected store between publications of the recovery.
func reopenRebootHookFixtureV4(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2, f *rebootScopeFixtureV4) (*v2Coordinator, error) {
	t.Helper()
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	s, err := openSharedStoreV2(c.store.root, c.store.budget, *c.store.access)
	if err != nil {
		return nil, err
	}
	// The hook reads the store that is being recovered, not the closed one.
	c.store = s
	opts := c.options
	opts.FreshScope, opts.RebootScope, opts.Routed, opts.RoutedIdentity = nil, f, a, a.identity
	b := v2BootID(a.identity.BootID)
	opts.BootID = &b
	opened, err := openCoordinatorV2(context.Background(), s, c.firewall, c.local, opts)
	t.Cleanup(func() {
		if opened != nil {
			opened.close()
		}
		_ = s.close()
	})
	return opened, err
}

// bootAgainFixtureV4 opens the selected store as one more complete kernel boot.
// The proof names whichever scope the store currently selects as the old one.
type bootAgainFixtureV4 struct {
	f         bootTerminalFixtureV4
	template  RoutedRebootScopeEvidenceV4
	scopes    []*boundaryAuthorityFixtureV2
	bootCount int
}

func (b *bootAgainFixtureV4) boot(t *testing.T, interruptAt string) (*v2Coordinator, *boundaryAuthorityFixtureV2, error) {
	t.Helper()
	c := b.f.c
	c.close()
	_ = c.store.close()
	s, err := openSharedStoreV2(c.store.root, c.store.budget, *c.store.access)
	if err != nil {
		t.Fatal(err)
	}
	c.store = s
	b.bootCount++
	next := freshBoundaryAuthorityV2(b.f.old)
	next.identity.BootID = string(rune('2'+b.bootCount)) + "2345678-1234-1234-1234-123456789abc"
	next.identity.RunID = strings.Repeat(string(rune('a'+b.bootCount)), 32)
	next.identity.Namespace, next.identity.Host = b.f.old.identity.Namespace, b.f.old.identity.Host
	// Root records every scope it created; the store selects one of them.
	retired := b.f.old.identity
	state := s.state
	work := ""
	if in := state.Configuration.Intent; in != nil && validHash(in.RoutedWork) {
		work = in.RoutedWork
	} else if state.RoutedActive != nil {
		work = state.RoutedActive.Work
	}
	if p, e := loadRoutedWorkV2(work, state.Lineage, s.readObject); e == nil {
		retired = p.Scope().Identity
	}
	if bd := state.RoutedBootBoundary; bd != nil && bd.CompletedBoot == "" && state.Configuration.Intent != nil {
		if p, e := loadRoutedWorkV2(bd.OldWork, state.Lineage, s.readObject); e == nil {
			retired = p.Scope().Identity
		}
	}
	proof := &rebootScopeFixtureV4{proof: b.template}
	proof.proof.Old, proof.proof.New = retired, next.identity
	bootAttestedFixtureV4(proof)
	opts := c.options
	opts.FreshScope, opts.RebootScope, opts.Routed, opts.RoutedIdentity = nil, proof, next, next.identity
	id := v2BootID(next.identity.BootID)
	opts.BootID = &id
	opts.Hook = nil
	if interruptAt == "reserve_archive_selected" || interruptAt == "reserve_archive_anchored" {
		s.hook = func(name string) error {
			d := s.state.RoutedDHCP
			if name == interruptAt && routedDHCPTerminalV3(d) && d.ColdSource != "" {
				return ErrInterrupted
			}
			return nil
		}
	}
	if interruptAt != "" {
		opts.Hook = func(name string) error {
			if name == interruptAt {
				return ErrInterrupted
			}
			return nil
		}
	}
	opened, err := openCoordinatorV2(context.Background(), s, c.firewall, c.local, opts)
	if opened != nil {
		c.firewall, c.local = opened.firewall, opened.local
		t.Cleanup(opened.close)
	}
	t.Cleanup(func() { _ = s.close() })
	b.scopes = append(b.scopes, next)
	return opened, next, err
}

// A scope replacement whose Startup boot was verified is finished and repeated
// from Startup on the next complete boot, keeping what was already archived.
// One whose own boot was still selected stays closed.
func TestRoutedBootTerminalV4RepeatsAnUnfinishedScopeReplacement(t *testing.T) {
	points := []string{"after_boot_intent", "after_boot_readback", "before_boot_completion", "after_boot_completion", "before_boot_boundary_completion", "after_boot_boundary_completion"}
	for _, kind := range []string{"pending confirm", "interrupted boot"} {
		for _, point := range points {
			t.Run(kind+"/"+point, func(t *testing.T) {
				var f bootTerminalFixtureV4
				if kind == "pending confirm" {
					c, old, principal, cfg := boundaryCoordinatorFixtureV2(t)
					reader := sharedBoundaryReaderV2(t, c, old)
					if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
						t.Fatal(err)
					}
					seconds := uint64(90)
					origin, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
					if err != nil {
						t.Fatal(err)
					}
					f = bootTerminalFixtureV4{c: c, old: old, reader: reader, subject: principal.Subject, operation: origin.ID, startup: result.Current.Startup.Hash}
				} else {
					f = interruptedRoutedFixtureV4(t, "commit")
				}
				_, proof := rebootAuthorityFixtureV4(t, f.c, f.old)
				again := &bootAgainFixtureV4{f: f, template: proof.proof}
				if kind == "interrupted boot" {
					// The first recovery boot is cut once its own intent is selected.
					if _, _, err := again.boot(t, "after_boot_intent"); !errors.Is(err, ErrInterrupted) {
						t.Fatal("first recovery boot was not interrupted", err)
					}
				}
				// This boot registers the scope replacement and is cut at the step.
				if _, _, err := again.boot(t, point); !errors.Is(err, ErrInterrupted) {
					t.Fatal("scope replacement was not interrupted at the publication step: ", err)
				}
				before, err := f.c.store.readRecordV2("selected.json", 4096)
				if err != nil {
					t.Fatal(err)
				}
				opened, last, err := again.boot(t, "")
				if strings.HasPrefix(point, "after_boot_intent") || point == "after_boot_readback" || point == "before_boot_completion" {
					// The replacement boot itself was still selected. Its system
					// reservation cannot be released before a later boot is verified,
					// so this selection stays closed and nothing is published.
					after, e := f.c.store.readRecordV2("selected.json", 4096)
					if !errors.Is(err, ErrRecovery) || e != nil || string(before) != string(after) || last.applies != 0 || last.bootstraps != 0 || last.arms != 0 || last.recovers != 0 {
						t.Fatal("selected replacement boot was not kept closed without effects: ", err, e)
					}
					return
				}
				if err != nil {
					t.Fatal("unfinished scope replacement was not repeated on the next complete boot: ", err)
				}
				cfg := opened.store.state.Configuration
				if cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired || cfg.Running.Hash != f.startup || last.current != f.startup || last.recovers != 0 {
					t.Fatal("repeated replacement did not select Startup in the new scope")
				}
				op, err := opened.store.lookupRetained(f.subject, f.operation)
				if err != nil || op.State != "final" || op.Pinned {
					t.Fatal("original transaction is not terminal after the repeated replacement", err)
				}
				superseded := 0
				for hash := cfg.AuditTip; hash != ""; {
					var audit v2CoordinatorAudit
					if e := opened.store.readObject(hash, &audit); e != nil {
						t.Fatal(e)
					}
					if audit.Result == "superseded_by_boot" && audit.OriginCommit == f.operation {
						superseded++
					}
					hash = audit.Previous
				}
				if kind == "pending confirm" && superseded != 1 {
					t.Fatal("pending Confirm was not archived exactly once", superseded)
				}
			})
		}
	}
}

func attestationAuditCountV4(t *testing.T, c *v2Coordinator) int {
	t.Helper()
	count := 0
	for hash := c.store.state.Configuration.AuditTip; hash != ""; {
		var audit v2CoordinatorAudit
		if err := c.store.readObject(hash, &audit); err != nil {
			t.Fatal(err)
		}
		if audit.Kind == bootAttestationAuditKindV4 {
			if audit.Result != bootAttestationAuditResultV4 || audit.Subject != "system" || audit.Operation == "" {
				t.Fatal("unexpected attestation audit entry")
			}
			var verified v2CoordinatorAudit
			if err := c.store.readObject(audit.Previous, &verified); err != nil || verified.Kind != v2BootKind ||
				verified.Result != "verified" || verified.Operation != audit.Operation || verified.Sequence+1 != audit.Sequence {
				t.Fatal("attestation did not follow its verified boot in the audit chain", err)
			}
			count++
		}
		hash = audit.Previous
	}
	return count
}

func TestRoutedBootTerminalV4AuditsAttestationOncePerBoot(t *testing.T) {
	for _, attested := range []bool{true, false} {
		name := "drain receipt"
		if attested {
			name = "boot attestation"
		}
		t.Run(name, func(t *testing.T) {
			c, old, principal, cfg := boundaryCoordinatorFixtureV2(t)
			m := c.store.reserves
			c.store = sharedTestStoreV2(t, c.store)
			c.store.reserves = m
			c.options.SharedReader = c.store.access
			if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
				t.Fatal(err)
			}
			seconds := uint64(90)
			if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
				t.Fatal(err)
			}
			fresh, proof := rebootAuthorityFixtureV4(t, c, old)
			want := 0
			if attested {
				bootAttestedFixtureV4(proof)
				want = 1
			}
			opened, err := reopenRebootFixtureV4(t, c, fresh, proof)
			if err != nil {
				t.Fatal(err)
			}
			if n := attestationAuditCountV4(t, opened); n != want {
				t.Fatal("unexpected number of attestation audit entries after the boot", n)
			}
			tip := opened.store.state.Configuration.AuditTip
			// A service restart during the same boot finds the entry and adds none.
			again, err := reopenRebootFixtureV4(t, opened, fresh, proof)
			if err != nil {
				t.Fatal("same-boot reopen after the audit entry failed: ", err)
			}
			if n := attestationAuditCountV4(t, again); n != want || again.store.state.Configuration.AuditTip != tip {
				t.Fatal("attestation audit entry was repeated for the same boot", n)
			}
		})
	}
}
