//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func reserveFutureRevisionV2(t *testing.T, base Config, label string, large bool) Revision {
	t.Helper()
	base = clone(base)
	base.Rules = nil
	if large {
		for i := range 64 {
			on := true
			rule := Rule{ID: fmt.Sprintf("%s-%02d-%s", label, i, strings.Repeat("r", 40)), Action: "allow", Match: &Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: PortRange{1, 65535}, DestinationPorts: PortRange{18080, 18080}}}
			if base.SchemaVersion == 4 {
				rule.Enabled = &on
			}
			base.Rules = append(base.Rules, rule)
		}
	}
	result, err := Canonical(base)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func reserveFutureFixtureV2(t *testing.T, domain, largePrevious string) (v2State, v2Configuration) {
	t.Helper()
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	state := clone(c.store.state)
	state.RecoveryReserveVersion = 1
	previous := clone(*state.Configuration)
	own := domainSnapshotV2(&previous, domain)
	small := reserveFutureRevisionV2(t, own.Running.Config, "small", false)
	large := reserveFutureRevisionV2(t, own.Running.Config, "large", true)
	own.Running, own.LastGood = small, small
	if largePrevious == "running" {
		own.Running = large
	}
	if largePrevious == "last-good" {
		own.LastGood = large
	}
	if err := previous.refresh(); err != nil {
		t.Fatal(err)
	}
	current := clone(*state.Configuration)
	own = domainSnapshotV2(&current, domain)
	own.Running, own.LastGood, own.Candidate = small, small, nil
	other := "local_services"
	if domain == "local_services" {
		other = "firewall"
	}
	adjacent := domainSnapshotV2(&current, other)
	candidate := reserveFutureRevisionV2(t, adjacent.Running.Config, "adjacent", true)
	adjacent.Candidate = &v2DomainCandidate{Owner: "other-current-owner", Base: adjacent.Running.Hash, Revision: candidate}
	if err := current.refresh(); err != nil {
		t.Fatal(err)
	}
	_, hash, err := v2Canonical(previous)
	if err != nil {
		t.Fatal(err)
	}
	current.Pending = &v2Confirmation{OriginCommit: "future-origin", Lease: "future-lease", Owner: p.Subject, Domain: domain, Previous: hash, Target: current.Running.Hash, Deadline: now.Add(time.Minute)}
	state.Configuration = &current
	return state, previous
}

func reserveFutureGrowRegistryV2(t *testing.T, state *v2State) {
	t.Helper()
	subject := state.Subjects[0].ID
	for i := len(state.Namespaces); ; i++ {
		core, _, err := v2Canonical(reserveMetadataCoreV2(*state))
		if err != nil {
			t.Fatal(err)
		}
		if len(core) >= 125*1024 {
			break
		}
		if i < int(state.NamespaceSlots) {
			state.Namespaces = append(state.Namespaces, v2Namespace{ID: fmt.Sprintf("future-ns-%d-%s", i, strings.Repeat("n", 90)), Subject: subject, Domain: "firewall", Closed: true, AdmitUntil: state.Clock.Add(time.Hour)})
			state.NamespaceSequence++
			continue
		}
		j := len(state.Subjects)
		if j >= int(state.SubjectSlots) {
			t.Fatal("registry fixture exhausted before boundary")
		}
		state.Subjects = append(state.Subjects, v2Subject{ID: fmt.Sprintf("future-subject-%d-%s", j, strings.Repeat("s", 90)), Login: fmt.Sprintf("future-login-%d-%s", j, strings.Repeat("u", 90)), CredentialRevision: checkpointDigest([]byte(fmt.Sprint(j))), Retired: true})
		state.SubjectSequence++
	}
	if !reserveMetadataStateFitsV2(*state) || !validV2Configuration(state.Configuration) {
		t.Fatal("current fixture must fit and remain canonical")
	}
}

func reserveFutureLoaderV2(t *testing.T, previous v2Configuration, calls *int) func(string, any) error {
	t.Helper()
	_, hash, err := v2Canonical(previous)
	if err != nil {
		t.Fatal(err)
	}
	return func(key string, value any) error {
		*calls++
		if key != hash {
			return errV2Unavailable
		}
		out, ok := value.(*v2Configuration)
		if !ok {
			return errV2Unavailable
		}
		*out = clone(previous)
		return nil
	}
}

func TestReserveFutureRestoresBothPreviousComponents(t *testing.T) {
	for _, domain := range []string{"firewall", "local_services"} {
		for _, component := range []string{"running", "last-good"} {
			t.Run(domain+"/"+component, func(t *testing.T) {
				state, previous := reserveFutureFixtureV2(t, domain, component)
				calls := 0
				if err := reserveMetadataFutureFitsV2(state, reserveFutureLoaderV2(t, previous, &calls)); err != nil {
					t.Fatal("roomy pending rejected", err)
				}
				reserveFutureGrowRegistryV2(t, &state)
				before := clone(state)
				calls = 0
				if err := reserveMetadataFutureFitsV2(state, reserveFutureLoaderV2(t, previous, &calls)); !errors.Is(err, errV2Limited) || calls != 1 {
					t.Fatal("registry consumed expiry component capacity", err, calls)
				}
				if !reflect.DeepEqual(before, state) {
					t.Fatal("forecast mutated selected declarations")
				}
				// The counterexample depends on retaining today's adjacent Candidate.
				lost := clone(state)
				lost.Configuration = &previous
				if !reserveMetadataStateFitsV2(lost) {
					t.Fatal("fixture does not distinguish an incorrect whole-snapshot restore")
				}
			})
		}
	}
}

func TestReserveFutureConfirmRetainsCapacity(t *testing.T) {
	state, previous := reserveFutureFixtureV2(t, "firewall", "")
	current := state.Configuration
	current.Firewall.Running = reserveFutureRevisionV2(t, current.Firewall.Running.Config, "confirm", true)
	if err := current.refresh(); err != nil {
		t.Fatal(err)
	}
	current.Pending.Target = current.Running.Hash
	reserveFutureGrowRegistryV2(t, &state)
	calls := 0
	if err := reserveMetadataFutureFitsV2(state, reserveFutureLoaderV2(t, previous, &calls)); !errors.Is(err, errV2Limited) || calls != 1 {
		t.Fatal("registry consumed Confirm LastGood capacity", err, calls)
	}
}

func TestReserveFutureNoPendingNeedsNoLoader(t *testing.T) {
	state, previous := reserveFutureFixtureV2(t, "firewall", "")
	pending := clone(state.Configuration.Pending)
	state.Configuration.Pending = nil
	calls := 0
	loader := func(string, any) error { calls++; return errV2Unavailable }
	if err := reserveMetadataFutureFitsV2(state, loader); err != nil || calls != 0 {
		t.Fatal(err, calls)
	}
	state.RecoveryReserveVersion = 0
	state.Configuration.Pending = &v2Confirmation{Previous: "malformed"}
	if err := reserveMetadataFutureFitsV2(state, loader); err != nil || calls != 0 {
		t.Fatal("legacy acquired new reads or checks", err, calls)
	}
	state.RecoveryReserveVersion = 1
	state.Configuration.Pending = pending
	if err := reserveMetadataFutureFitsV2(state, reserveFutureLoaderV2(t, previous, &calls)); err != nil || calls != 1 {
		t.Fatal("pending snapshot must load exactly once", err, calls)
	}
}

func TestReserveFutureRejectsMissingOrMalformedPrevious(t *testing.T) {
	for _, kind := range []string{"missing-loader", "load-error", "wrong-hash", "invalid-revision", "previous-intent", "previous-pending"} {
		t.Run(kind, func(t *testing.T) {
			state, previous := reserveFutureFixtureV2(t, "firewall", "")
			calls := 0
			loader := reserveFutureLoaderV2(t, previous, &calls)
			switch kind {
			case "missing-loader":
				loader = nil
			case "load-error":
				loader = func(string, any) error { calls++; return ErrInvalid }
			case "wrong-hash":
				previous.Firewall.Generation++
				loader = func(_ string, v any) error { calls++; *v.(*v2Configuration) = clone(previous); return nil }
			case "invalid-revision":
				previous.Firewall.Running.Hash = strings.Repeat("a", 64)
			case "previous-intent":
				previous.Intent = &v2CoordinatorIntent{Operation: "other", Subject: "other", Domain: "firewall", Kind: OpStage, Previous: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), TargetGeneration: 1}
			case "previous-pending":
				previous.Pending = clone(state.Configuration.Pending)
				previous.Pending.Target = previous.Running.Hash
			}
			if kind == "invalid-revision" || kind == "previous-intent" || kind == "previous-pending" {
				_, hash, _ := v2Canonical(previous)
				state.Configuration.Pending.Previous = hash
				loader = reserveFutureLoaderV2(t, previous, &calls)
			}
			if err := reserveMetadataFutureFitsV2(state, loader); !errors.Is(err, errV2Unavailable) || errors.Is(err, errV2Limited) {
				t.Fatal("corruption classified as capacity", err)
			}
			expected := 1
			if kind == "missing-loader" {
				expected = 0
			}
			if calls != expected {
				t.Fatal("unexpected previous reads", calls)
			}
		})
	}
}

func TestReservePredictorMatchesCoordinatorTerminalDomains(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	original := c.store.state.Configuration.Running.Hash
	coordinatorV2Stage(t, c, p, "predictor")
	zero := uint64(0)
	op := v2Operation{ID: "predictor-op", Sequence: 500, Subject: p.Subject, Domain: "firewall", Request: v2Request{Kind: OpCommit, ConfirmSeconds: &zero}}
	predicted, err := reserveTargetEnvelopeV2(c.store, op)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := c.targetLocked(op, clone(*c.store.state.Configuration), c.now())
	if err != nil || !reflect.DeepEqual(predicted, actual) || predicted.Firewall.LastGood.Hash != predicted.Firewall.Running.Hash {
		t.Fatal("Commit0 predictor differs", err)
	}
	coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	op.Request = v2Request{Kind: OpRollback, Target: original}
	predicted, err = reserveTargetEnvelopeV2(c.store, op)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err = c.targetLocked(op, clone(*c.store.state.Configuration), c.now())
	if err != nil || !reflect.DeepEqual(predicted, actual) || predicted.Firewall.LastGood.Hash != predicted.Firewall.Running.Hash {
		t.Fatal("firewall rollback predictor differs", err)
	}
	state := c.store.state.Configuration
	state.RecoveryRequired = true
	state.Intent = &v2CoordinatorIntent{Operation: "recover-intent", Subject: p.Subject, Domain: "firewall", Kind: OpRecover, Previous: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), TargetGeneration: c.store.state.Generation}
	state.Pending = &v2Confirmation{OriginCommit: "recover-origin", Owner: p.Subject, Domain: "firewall", Lease: "recover-lease", Previous: strings.Repeat("a", 64), Target: state.Running.Hash, Deadline: c.now().Add(time.Minute)}
	op.Request = v2Request{Kind: OpRecover}
	predicted, err = reserveTargetEnvelopeV2(c.store, op)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err = c.targetLocked(op, clone(*state), c.now())
	if err != nil || !reflect.DeepEqual(predicted, actual) || predicted.Pending != nil || predicted.RecoveryRequired {
		t.Fatal("Recover flags differ", err)
	}
}

func TestReserveFuturePublishCorruptionRetainsFenceAndRejectsConfirm(t *testing.T) {
	for _, kind := range []string{"missing", "intent", "nested-pending", "invalid-config"} {
		t.Run(kind, func(t *testing.T) {
			c, _, engines, p, now := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			coordinatorV2Stage(t, c, p, "future-publish-fence")
			seconds := uint64(90)
			committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			ns, err := c.store.namespace(p.Subject, "firewall", *now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			child, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Running.Hash}, *now)
			if err != nil {
				t.Fatal(err)
			}
			proposed := clone(c.store.state)
			proposed.Clock = now.Add(time.Millisecond)
			previousHash := proposed.Configuration.Pending.Previous
			if kind == "missing" {
				name, _ := v2ObjectName(previousHash)
				if err = c.store.root.Remove(name); err != nil {
					t.Fatal(err)
				}
			} else {
				var previous v2Configuration
				if err = c.store.readObject(previousHash, &previous); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "intent":
					previous.Intent = &v2CoordinatorIntent{Operation: "semantically-invalid-predecessor", Subject: p.Subject, Domain: "firewall", Kind: OpStage, Previous: previousHash, Target: previousHash, TargetGeneration: proposed.Generation}
				case "nested-pending":
					previous.Pending = &v2Confirmation{OriginCommit: "nested-origin", Lease: "nested-lease", Owner: p.Subject, Domain: "firewall", Previous: previousHash, Target: previous.Running.Hash, Deadline: now.Add(time.Minute)}
				case "invalid-config":
					previous.Firewall.Running.Hash = strings.Repeat("a", 64)
				}
				hash, e := c.store.object(previous)
				if e != nil {
					t.Fatal(e)
				}
				proposed.Configuration.Pending.Previous = hash
			}
			before := clone(c.store.state)
			selector := c.store.selector
			for _, engine := range engines {
				engine.reset()
			}
			if err = c.store.publish(proposed); !errors.Is(err, errV2Unavailable) || errors.Is(err, errV2Limited) || !c.store.blocked || c.store.selector != selector || !reflect.DeepEqual(c.store.state, before) {
				t.Fatal("corruption escaped unavailability fence", err)
			}
			if _, err = c.execute(context.Background(), p, child.ID); !errors.Is(err, errV2Unavailable) {
				t.Fatal("confirmation passed corruption fence", err)
			}
			for _, engine := range engines {
				if engine.applies.Load() != 0 || engine.reads.Load() != 0 || engine.validations.Load() != 0 {
					t.Fatal("corrupted historical context reached engines")
				}
			}
		})
	}
}
