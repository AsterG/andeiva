//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type countedCoordinatorV2Engine struct {
	base                        *SimEngine
	applies, validations, reads atomic.Int64
	watch                       string
	watchApplies                atomic.Int64
}

func (e *countedCoordinatorV2Engine) Name() string { return e.base.Name() }
func (e *countedCoordinatorV2Engine) Validate(config Config) error {
	e.validations.Add(1)
	return e.base.Validate(config)
}
func (e *countedCoordinatorV2Engine) Current() string { e.reads.Add(1); return e.base.Current() }
func (e *countedCoordinatorV2Engine) Apply(ctx context.Context, revision Revision) error {
	e.applies.Add(1)
	if revision.Hash == e.watch {
		e.watchApplies.Add(1)
	}
	return e.base.Apply(ctx, revision)
}
func (e *countedCoordinatorV2Engine) reset() {
	e.applies.Store(0)
	e.validations.Store(0)
	e.reads.Store(0)
}

func coordinatorV2Fixture(t *testing.T, automatic bool) (*v2Coordinator, *os.Root, []*countedCoordinatorV2Engine, v2TrustedPrincipal, *time.Time) {
	t.Helper()
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	local, _ := v2LegacyFixture(t, "local_services", 27)
	fwImage, err := inspectLegacyV2(fw, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	lsImage, err := inspectLegacyV2(local, "local_services", nil)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := v2ID("subject", 1)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []v2LegacyBinding{{Source: fwImage.Source, Actor: "alice", Subject: subject, ReceiptIndex: fwImage.ReceiptIndex}, {Source: lsImage.Source, Actor: "alice", Subject: subject, ReceiptIndex: lsImage.ReceiptIndex}}
	area, _ := checkpointFixtureArea(t)
	now := time.Now().UTC()
	store, err := prepareMigrationV2(area, fw, local, []v2Subject{{ID: subject, Login: "alice", CredentialRevision: checkpointDigest([]byte("credential revision"))}}, bindings, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	engines := []*countedCoordinatorV2Engine{{base: NewSimEngine("fw-first")}, {base: NewSimEngine("fw-second")}, {base: NewSimEngine("local-only")}}
	engines[0].base.Drift(fwImage.Snapshot.Running.Hash)
	engines[1].base.Drift(fwImage.Snapshot.Running.Hash)
	engines[2].base.Drift(lsImage.Snapshot.Running.Hash)
	clock := func() time.Time { return now }
	if automatic {
		clock = func() time.Time { return time.Now().UTC() }
	}
	c, err := openCoordinatorV2(context.Background(), store, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, v2CoordinatorOptions{Now: clock, ManualTimeout: !automatic})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.close(); _ = store.close() })
	return c, area, engines, v2TrustedPrincipal{Subject: subject, Role: RoleAdmin}, &now
}

func coordinatorV2Rule(id string) Config {
	on := true
	return Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{{ID: id, Action: "allow", Enabled: &on, Match: &Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: PortRange{1, 65535}, DestinationPorts: PortRange{18080, 18080}}}}}
}
func coordinatorV2Request(t *testing.T, c *v2Coordinator, p v2TrustedPrincipal, request v2Request) (v2Operation, v2CoordinatorResult, error) {
	t.Helper()
	_, generation, err := c.status(p)
	if err != nil {
		return v2Operation{}, v2CoordinatorResult{}, err
	}
	namespace, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
	if err != nil {
		return v2Operation{}, v2CoordinatorResult{}, err
	}
	op, err := c.store.admit(p.Subject, namespace.ID, generation, request, c.now())
	if err != nil {
		return v2Operation{}, v2CoordinatorResult{}, err
	}
	result, err := c.execute(context.Background(), p, op.ID)
	return op, result, err
}
func coordinatorV2Run(t *testing.T, c *v2Coordinator, p v2TrustedPrincipal, request v2Request) v2CoordinatorResult {
	t.Helper()
	_, result, err := coordinatorV2Request(t, c, p, request)
	if err != nil {
		t.Fatalf("%s: %v", request.Kind, err)
	}
	return result
}
func coordinatorV2Stage(t *testing.T, c *v2Coordinator, p v2TrustedPrincipal, id string) v2CoordinatorResult {
	t.Helper()
	config := coordinatorV2Rule(id)
	return coordinatorV2Run(t, c, p, v2Request{Kind: OpStage, Config: &config})
}

func TestCoordinatorV2LifecycleAndIndependentProjections(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	initial, generation, err := c.status(p)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 1 || initial.Firewall.Generation != 9 || initial.LocalServices.Generation != 27 || c.store.state.Operational {
		t.Fatal("wrong initial lineage/projection")
	}
	stage := coordinatorV2Stage(t, c, p, "first")
	if stage.GlobalGeneration != 2 || stage.Current.Firewall.Generation != 10 || stage.Current.LocalServices.Generation != 27 || stage.Current.Running.Hash != initial.Running.Hash || stage.Current.Candidate == nil {
		t.Fatal("candidate/running coupled")
	}
	validated := coordinatorV2Run(t, c, p, v2Request{Kind: OpValidate})
	if validated.GlobalGeneration != 2 || validated.Current.Firewall.Generation != 10 {
		t.Fatal("validation observation invented generation")
	}
	window := uint64(30)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &window})
	if committed.Current.Pending == nil || committed.Operation.Outcome.Code != "applied_pending_confirmation" || !committed.Operation.Pinned {
		t.Fatal("confirmed commit missing lease")
	}
	for _, engine := range engines[:2] {
		if engine.Current() != committed.Current.Firewall.Running.Hash {
			t.Fatal("effective running mismatch")
		}
	}
	if committed.Current.Startup.Hash != initial.Startup.Hash {
		t.Fatal("commit overwrote Startup")
	}
	originBefore := clone(committed.Operation.Outcome)
	confirmed := coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Running.Hash})
	if confirmed.Current.Pending != nil || confirmed.Current.Firewall.LastGood.Hash != confirmed.Current.Firewall.Running.Hash {
		t.Fatal("confirm failed")
	}
	origin, err := c.store.lookup(p.Subject, committed.Operation.ID)
	if err != nil || origin.Pinned || !reflect.DeepEqual(originBefore, origin.Outcome) {
		t.Fatal("historical outcome rewritten", err)
	}
	saved := coordinatorV2Run(t, c, p, v2Request{Kind: OpSave})
	if saved.Current.Firewall.Startup.Hash != saved.Current.Firewall.Running.Hash || saved.Current.LocalServices.Startup.Hash != initial.LocalServices.Startup.Hash {
		t.Fatal("domain Save overwrote unrelated Startup")
	}
	rolled := coordinatorV2Run(t, c, p, v2Request{Kind: OpRollback, Target: initial.Running.Hash})
	if rolled.Current.Running.Hash != initial.Running.Hash || rolled.Current.Startup.Hash != saved.Current.Startup.Hash {
		t.Fatal("rollback coupled Startup")
	}
	if c.store.state.ReservedBytes != 0 || c.store.state.ReservedInodes != 0 {
		t.Fatal("completed lifecycle leaked reservations")
	}
	replayed, err := c.execute(context.Background(), p, committed.Operation.ID)
	if err != nil || !reflect.DeepEqual(replayed.Operation.Outcome, originBefore) || replayed.Current.Running.Hash != rolled.Current.Running.Hash {
		t.Fatal("historical result confused with current", err)
	}
	for _, domain := range []string{"firewall", "local_services"} {
		projection, original, e := c.store.legacyReplay(p.Subject, domain, "alice", "retained-key", checkpointDigest([]byte("request")))
		want := rolled.Current.Firewall.Generation
		if domain == "local_services" {
			want = 27
		}
		if e != nil || projection.Generation != want || original != 3 {
			t.Fatal("legacy current/original projection", domain, e)
		}
	}
}

func TestCoordinatorV2DeniesLocalServicesAndUnauthorizedBeforeEngines(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	ns, err := c.store.namespace(p.Subject, "local_services", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpValidate}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	for _, engine := range engines {
		engine.reset()
	}
	for _, principal := range []v2TrustedPrincipal{{Subject: p.Subject, Role: RoleViewer}, {Subject: "foreign", Role: RoleAdmin}, p} {
		if _, err = c.execute(context.Background(), principal, op.ID); !errors.Is(err, ErrDenied) {
			t.Fatal("write admitted without proven authority/evidence", err)
		}
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 || engine.validations.Load() != 0 || engine.reads.Load() != 0 {
			t.Fatal("denied local write reached engine")
		}
	}
	stored, err := c.store.lookup(p.Subject, op.ID)
	if err != nil || stored.State != "accepted" {
		t.Fatal("denied request created effects", err)
	}
}

func TestCoordinatorV2AutomaticTimeoutWithoutAdministrator(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, engines, p, _ := coordinatorV2Fixture(t, true)
		initial, _, _ := c.status(p)
		coordinatorV2Stage(t, c, p, "timed")
		seconds := uint64(30)
		commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
		if _, err := c.store.changeSubject(p.Subject, "alice", c.store.state.Subjects[0].CredentialRevision, true, c.now()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Second)
		synctest.Wait()
		state := c.store.state.Configuration
		if state.Pending != nil || state.Intent != nil || state.Running.Hash != initial.Running.Hash {
			t.Fatal("timer depended on active subject or namespace")
		}
		for _, engine := range engines[:2] {
			if engine.Current() != initial.Firewall.Running.Hash {
				t.Fatal("timeout did not restore effective configuration")
			}
		}
		recovery, err := c.recoveryStatus()
		if err != nil || recovery.State != "final" || recovery.Origin != commit.Operation.ID || recovery.Lease != commit.Current.Pending.Lease {
			t.Fatal("recovery linkage", err)
		}
		origin, err := c.store.lookupRetained(p.Subject, commit.Operation.ID)
		if err != nil || origin.Pinned || origin.Outcome.Code != "applied_pending_confirmation" {
			t.Fatal("origin mutated/left pinned", err)
		}
		if c.store.state.ReservedBytes != 0 {
			t.Fatal("timeout reservation retained")
		}
	})
}

func TestCoordinatorV2RejectsWrongConfirmationAndGlobalTargets(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	coordinatorV2Stage(t, c, p, "confirm")
	seconds := uint64(30)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	for _, request := range []v2Request{{Kind: OpConfirm, Origin: "forged", Target: commit.Current.Running.Hash}, {Kind: OpConfirm, Origin: commit.Operation.ID, Target: commit.Current.Firewall.Running.Hash}} {
		_, _, err := coordinatorV2Request(t, c, p, request)
		if !errors.Is(err, ErrConflict) {
			t.Fatal("wrong origin/target confirmed", err)
		}
	}
	coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: commit.Operation.ID, Target: commit.Current.Running.Hash})
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpRollback, Target: commit.Current.Firewall.Running.Hash})
	if !errors.Is(err, ErrInvalid) || c.store.blocked {
		t.Fatal("typed wrong target fenced the store", err)
	}
	if c.store.state.Configuration.Pending != nil {
		t.Fatal("pending remained after correct confirmation")
	}
	local, _, err := c.store.legacyReplay(p.Subject, "local_services", "alice", "retained-key", checkpointDigest([]byte("request")))
	if err != nil || local.Pending != nil || local.Running.Config.SchemaVersion != 3 {
		t.Fatal("firewall pending leaked into local projection", err)
	}
}

func TestCoordinatorV2CanonicalCompositeDomainBinding(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	state, _, _ := c.status(p)
	canonical, err := CanonicalComposite(state.Running.Config)
	if err != nil || canonical.Hash != state.Running.Hash || canonical.Hash == state.Firewall.Running.Hash || canonical.Hash == state.LocalServices.Running.Hash {
		t.Fatal("composite reused a component hash", err)
	}
	bad := clone(state.Running.Config)
	bad.Domains.Network = &v2ComponentReference{Schema: 4, Revision: state.Firewall.Running.Hash}
	if _, err = CanonicalComposite(bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("unavailable network schema accepted")
	}
	if canonical.Config.Domains.Firewall.Revision != state.Firewall.Running.Hash {
		t.Fatal(fmt.Sprint("component reference changed"))
	}
}
