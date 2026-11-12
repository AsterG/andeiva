//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func reopenCoordinatorV2(t *testing.T, prior *v2Coordinator, area *os.Root) (*v2Coordinator, error) {
	t.Helper()
	prior.close()
	if err := prior.store.close(); err != nil {
		t.Fatal(err)
	}
	store, err := openV2(area, prior.store.budget)
	if err != nil {
		return nil, err
	}
	options := prior.options
	options.Hook = nil
	c, err := openCoordinatorV2(context.Background(), store, prior.firewall, prior.local, options)
	t.Cleanup(func() {
		if c != nil {
			c.close()
		}
		_ = store.close()
	})
	return c, err
}

func TestCoordinatorV2PartialFailureCompensatesBeforeFinalPublication(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "partial")
	before := clone(*c.store.state.Configuration)
	engines[1].base.FailNext("after")
	seconds := uint64(0)
	op, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrEngine) || result.Operation.State != "final" || result.Operation.Outcome.Code != "failed_rolled_back" {
		t.Fatal("failure published success", err)
	}
	if result.Current.Running.Hash != initial.Running.Hash || result.Current.Startup.Hash != before.Startup.Hash || result.Current.Intent != nil || result.Current.RecoveryRequired {
		t.Fatal("compensation lost state")
	}
	for _, engine := range engines[:2] {
		if engine.Current() != initial.Firewall.Running.Hash {
			t.Fatal("partial engine configuration persisted")
		}
	}
	replay, err := c.execute(context.Background(), p, op.ID)
	if err != nil || replay.Operation.Outcome.Code != "failed_rolled_back" {
		t.Fatal("failed outcome not exactly replayable", err)
	}
}

func TestCoordinatorV2UnknownCompensationPinsAndRecoversOnRestart(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "uncertain")
	engines[0].base.SetFailure(initial.Firewall.Running.Hash, "before")
	engines[1].base.FailNext("before")
	seconds := uint64(0)
	op, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrRecovery) || result.Operation.State != "uncertain" || !result.Operation.Pinned || !result.Current.RecoveryRequired || result.Current.Intent == nil {
		t.Fatal("uncertainty was not durably pinned", err)
	}
	if result.Current.Running.Hash != initial.Running.Hash || c.store.state.ReservedBytes == 0 {
		t.Fatal("unverified target published or reserve lost")
	}
	_, _, err = coordinatorV2Request(t, c, p, v2Request{Kind: OpSave})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal("conflicting mutation was allowed", err)
	}
	engines[0].base.ClearFailure()
	resumed, err := reopenCoordinatorV2(t, c, area)
	if err != nil {
		t.Fatal("recovery reopen", err)
	}
	got, err := resumed.store.lookup(p.Subject, op.ID)
	if err != nil || got.State != "final" || got.Pinned || got.Outcome.Code != "failed_rolled_back" {
		t.Fatal("pending execution replayed/lost", err)
	}
	state, _, err := resumed.status(p)
	if err != nil || state.Intent != nil || state.RecoveryRequired || state.Running.Hash != initial.Running.Hash {
		t.Fatal("recovery falsely selected target", err)
	}
}

func TestCoordinatorV2InterruptionBoundariesNeverReplayTarget(t *testing.T) {
	for _, point := range []string{"after_intent", "after_component_apply", "after_readback"} {
		t.Run(point, func(t *testing.T) {
			c, area, engines, p, _ := coordinatorV2Fixture(t, false)
			initial, _, _ := c.status(p)
			staged := coordinatorV2Stage(t, c, p, "interrupt")
			for _, engine := range engines[:2] {
				engine.watch = staged.Current.Firewall.Candidate.Revision.Hash
				engine.watchApplies.Store(0)
			}
			c.options.Hook = func(at string) error {
				if at == point {
					return ErrInterrupted
				}
				return nil
			}
			seconds := uint64(0)
			op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal("boundary did not interrupt", err)
			}
			targetEffects := engines[0].watchApplies.Load() + engines[1].watchApplies.Load()
			resumed, err := reopenCoordinatorV2(t, c, area)
			if err != nil {
				t.Fatal(err)
			}
			if engines[0].watchApplies.Load()+engines[1].watchApplies.Load() != targetEffects {
				t.Fatal("target effects replayed after restart")
			}
			got, err := resumed.store.lookup(p.Subject, op.ID)
			if err != nil || got.Outcome == nil || got.Outcome.Code != "failed_rolled_back" {
				t.Fatal("interrupted operation falsely succeeded", err)
			}
			if resumed.store.state.Configuration.Running.Hash != initial.Running.Hash {
				t.Fatal("unverified revision survived restart")
			}
		})
	}
}

func TestCoordinatorV2RestartRevertsUnconfirmedWithImmutableOutcome(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "restart-lease")
	seconds := uint64(30)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	outcome := clone(commit.Operation.Outcome)
	resumed, err := reopenCoordinatorV2(t, c, area)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := resumed.status(p)
	if err != nil || state.Pending != nil || state.Running.Hash != initial.Running.Hash || state.Startup.Hash != initial.Startup.Hash {
		t.Fatal("restart failed to restore previous configuration", err)
	}
	for _, engine := range engines[:2] {
		if engine.Current() != initial.Firewall.Running.Hash {
			t.Fatal("restart did not verify rollback")
		}
	}
	stored, err := resumed.store.lookup(p.Subject, commit.Operation.ID)
	if err != nil || stored.Pinned || !reflect.DeepEqual(stored.Outcome, outcome) {
		t.Fatal("historical confirmed-commit outcome rewritten", err)
	}
	recovery, err := resumed.recoveryStatus()
	if err != nil || recovery.Kind != "restart" || recovery.State != "final" || recovery.Origin != commit.Operation.ID {
		t.Fatal("restart linkage missing", err)
	}
}

func TestCoordinatorV2FinalStorageFailureNeverReturnsSuccess(t *testing.T) {
	for _, point := range []string{"before_select", "after_select"} {
		t.Run(point, func(t *testing.T) {
			c, _, engines, p, _ := coordinatorV2Fixture(t, false)
			initial, _, _ := c.status(p)
			coordinatorV2Stage(t, c, p, "storage")
			count := 0
			c.store.hook = func(at string) error {
				if at == point {
					count++
					if count == 3 {
						return ErrInterrupted
					}
				}
				return nil
			}
			// Admission is selection1, intent selection2, outcome selection3.
			seconds := uint64(0)
			_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if err == nil {
				t.Fatal("ambiguous outcome returned success")
			}
			if point == "before_select" {
				if !c.store.blocked {
					t.Fatal("unselected staging did not fence writes")
				}
				for _, engine := range engines[:2] {
					if engine.Current() != initial.Firewall.Running.Hash {
						t.Fatal("storage failure left new enforcement")
					}
				}
				if _, err = c.store.root.Stat("selection.pending"); err != nil {
					t.Fatal("unknown staging was cleaned", err)
				}
			} else {
				if c.store.blocked || !c.readback(*c.store.state.Configuration) {
					t.Fatal("durable selected result was not reconciled")
				}
			}
		})
	}
}

func TestCoordinatorV2ConcurrentExecutorsHaveOneEffectAndStableReplay(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	coordinatorV2Stage(t, c, p, "concurrent")
	seconds := uint64(0)
	ns, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	for _, engine := range engines {
		engine.reset()
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := c.execute(context.Background(), p, op.ID)
			if e != nil || result.Operation.State != "final" {
				t.Errorf("concurrent replay: %v", e)
			}
		}()
	}
	wg.Wait()
	if engines[0].applies.Load() != 1 || engines[1].applies.Load() != 1 || engines[2].applies.Load() != 0 {
		t.Fatal("concurrent callers repeated effects")
	}
}

func TestCoordinatorV2MonotonicLeaseSurvivesBackwardWallClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, _, p, _ := coordinatorV2Fixture(t, true)
		var skew atomic.Int64
		c.options.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())).UTC() }
		initial, _, _ := c.status(p)
		coordinatorV2Stage(t, c, p, "clock")
		seconds := uint64(30)
		coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
		clockBefore := c.store.state.Clock
		skew.Store(-int64(time.Hour))
		if err := c.tick(context.Background(), c.now()); !errors.Is(err, errV2Unavailable) {
			t.Fatal("backward clock not detected", err)
		}
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if c.store.state.Configuration.Pending != nil || c.store.state.Configuration.Running.Hash != initial.Running.Hash || c.store.state.Clock.Before(clockBefore) {
			t.Fatal("wall clock extended lease or backdated state")
		}
	})
}

func TestCoordinatorV2RecoverLastGoodAndAuditChain(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	coordinatorV2Stage(t, c, p, "recover")
	zero := uint64(0)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	engines[0].base.Drift(checkpointDigest([]byte("unverified simulated component")))
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpSave})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal("drift did not block save", err)
	}
	recovered := coordinatorV2Run(t, c, p, v2Request{Kind: OpRecover})
	if recovered.Current.Running.Hash != committed.Current.LastGood.Hash || recovered.Current.Startup.Hash != committed.Current.Startup.Hash || recovered.Current.Intent != nil || recovered.Current.RecoveryRequired {
		t.Fatal("Recover did not restore verified LastGood")
	}
	for _, engine := range engines[:2] {
		if engine.Current() != recovered.Current.Firewall.Running.Hash {
			t.Fatal("Recover returned before readback")
		}
	}
	hash := recovered.Current.AuditTip
	for sequence := recovered.Current.AuditSequence; sequence > 0; sequence-- {
		var audit v2CoordinatorAudit
		if err = c.store.readObject(hash, &audit); err != nil || audit.Format != v2Format || audit.Sequence != sequence || audit.Operation == "" {
			t.Fatal("protected audit chain", err)
		}
		hash = audit.Previous
	}
	if hash != "" {
		t.Fatal("audit chain lost origin")
	}
}

func TestCoordinatorV2ReadbackAllComponentsBeforePublishing(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "global-readback")
	c.options.Hook = func(point string) error {
		if point == "after_component_apply" {
			engines[2].base.Drift(checkpointDigest([]byte("local listener drift")))
		}
		return nil
	}
	zero := uint64(0)
	_, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrRecovery) || !result.Current.RecoveryRequired || result.Operation.State != "uncertain" || result.Current.Running.Hash != initial.Running.Hash {
		t.Fatal("unverified global target was published", err)
	}
	if engines[2].applies.Load() != 0 {
		t.Fatal("coordinator changed unproven local service engine")
	}
}

func TestCoordinatorV2RollbackRequiresVerifiedHistory(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	staged := coordinatorV2Stage(t, c, p, "unverified-candidate")
	for _, engine := range engines {
		engine.reset()
	}
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpRollback, Target: staged.Current.Candidate.Hash})
	if !errors.Is(err, ErrInvalid) || c.store.blocked {
		t.Fatal("persisted Candidate became rollback authority", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("unverified rollback reached Apply")
		}
	}
	seconds := uint64(30)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if _, known, e := c.verifiedLookup(c.store.state.Configuration.VerifiedIndex, commit.Current.Running.Hash); e != nil || known {
		t.Fatal("unconfirmed commit marked verified", e)
	}
	coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: commit.Operation.ID, Target: commit.Current.Running.Hash})
	if _, known, e := c.verifiedLookup(c.store.state.Configuration.VerifiedIndex, commit.Current.Running.Hash); e != nil || !known {
		t.Fatal("confirmed revision lost durable witness", e)
	}
}

func TestCoordinatorV2ApplyPastDeadlineCompensates(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "slow-apply")
	once := false
	c.options.Hook = func(point string) error {
		if point == "after_component_apply" && !once {
			once = true
			*now = now.Add(31 * time.Second)
		}
		return nil
	}
	seconds := uint64(30)
	_, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrExpired) || result.Operation.Outcome == nil || result.Operation.Outcome.Code != "failed_rolled_back" || result.Operation.Outcome.ErrorCode != ErrExpired.Error() || result.Current.Pending != nil || result.Current.Running.Hash != initial.Running.Hash {
		t.Fatal("late application published pending success", err)
	}
}

func TestCoordinatorV2InterruptedRecoveryRetainsIdentityAndReservation(t *testing.T) {
	c, area, _, p, now := coordinatorV2Fixture(t, false)
	initial, _, _ := c.status(p)
	coordinatorV2Stage(t, c, p, "recovery-interruption")
	seconds := uint64(30)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	c.options.Hook = func(point string) error {
		if point == "after_recovery_intent" {
			return ErrInterrupted
		}
		return nil
	}
	*now = now.Add(31 * time.Second)
	if err := c.tick(context.Background(), *now); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	pending, err := c.recoveryStatus()
	if err != nil || pending.State != "pending" || pending.Origin != commit.Operation.ID {
		t.Fatal("recovery identity not persisted", err)
	}
	if c.store.state.ReservedBytes != v2OperationReserveBytes {
		t.Fatal("interrupted recovery lost reservation")
	}
	resumed, err := reopenCoordinatorV2(t, c, area)
	if err != nil {
		t.Fatal(err)
	}
	final, err := resumed.recoveryStatus()
	if err != nil || final.ID != pending.ID || final.State != "final" {
		t.Fatal("restart fabricated another recovery operation", err)
	}
	if resumed.store.state.Configuration.Running.Hash != initial.Running.Hash || resumed.store.state.ReservedBytes != 0 {
		t.Fatal("recovery did not verify previous state before releasing reserve")
	}
}

func TestCoordinatorV2RawCatalogueCannotBypassAtomicExecutor(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	ns, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpSave}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.store.begin(p.Subject, op.ID, c.now()); !errors.Is(err, errV2Invalid) {
		t.Fatal("raw begin bypassed coordinator intent", err)
	}
	if _, err = c.store.finish(p.Subject, op.ID, v2Outcome{Code: "applied", Generation: c.store.state.Generation}, []byte("not an effect proof"), c.now(), false); !errors.Is(err, errV2Invalid) {
		t.Fatal("raw finish bypassed state/audit selection", err)
	}
	stored, err := c.store.lookup(p.Subject, op.ID)
	if err != nil || stored.State != "accepted" {
		t.Fatal("raw bypass changed request", err)
	}
	if _, err = c.execute(context.Background(), p, op.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorV2AttachRefusesUntrackedPreparationIntent(t *testing.T) {
	store, _, now, subject := v2Fixture(t, 64)
	ns, err := store.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := store.admit(subject, ns.ID, 1, v2Request{Kind: OpValidate}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.begin(subject, op.ID, now); err != nil {
		t.Fatal(err)
	}
	fw := &countedCoordinatorV2Engine{base: NewSimEngine("untracked-fw")}
	local := &countedCoordinatorV2Engine{base: NewSimEngine("untracked-local")}
	if c, err := openCoordinatorV2(context.Background(), store, []Engine{fw}, []Engine{local}, v2CoordinatorOptions{ManualTimeout: true}); !errors.Is(err, ErrRecovery) {
		if c != nil {
			c.close()
		}
		t.Fatal("untracked preparation work was adopted", err)
	}
	if store.state.Configuration != nil || fw.applies.Load() != 0 || fw.reads.Load() != 0 || local.reads.Load() != 0 {
		t.Fatal("attach applied or observed engines before resolving unknown intent")
	}
}
