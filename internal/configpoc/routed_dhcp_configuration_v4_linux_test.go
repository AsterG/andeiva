//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// Contract projection only. The legacy writer deliberately still refuses this
// active-WAN publication; this is not runtime activation or physical evidence.
type dhcpConfigurationFixtureV4 struct {
	x      v4RoutedDHCPConfiguration
	state  v2State
	op     v2Operation
	seed   map[string][]byte
	store  *v2Store
	source v2State
	header *v4RoutedDHCPConfigurationState
}

func (f *dhcpConfigurationFixtureV4) object(t *testing.T, value any) string {
	t.Helper()
	raw, hash, err := v2Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	f.seed[hash] = raw
	return hash
}
func (f *dhcpConfigurationFixtureV4) load(hash string, value any) error {
	if raw, ok := f.seed[hash]; ok {
		return checkpointDecode(raw, value)
	}
	return f.store.readObject(hash, value)
}
func (f *dhcpConfigurationFixtureV4) lookup(subject, id string) (v2Operation, error) {
	if f.op.Subject != subject || f.op.ID != id {
		return v2Operation{}, ErrRecovery
	}
	return clone(f.op), nil
}

func (f *dhcpConfigurationFixtureV4) installObjects(t *testing.T) {
	t.Helper()
	for hash, raw := range f.seed {
		name, _ := v2ObjectName(hash)
		if _, err := f.store.root.Lstat(name); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := f.store.root.WriteFile(name, raw, 0640); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *dhcpConfigurationFixtureV4) graph(t *testing.T) *v2ReachabilityReader {
	t.Helper()
	root, err := f.store.root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	return &v2ReachabilityReader{ctx: context.Background(), area: f.store.root, root: root, shared: f.store.access, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
}

func dhcpConfigurationContractFixtureV4(t *testing.T) *dhcpConfigurationFixtureV4 {
	t.Helper()
	w, a := dhcpStoreFixtureV3(t)
	return dhcpConfigurationContractFromV4(t, w, a)
}

func dhcpConfigurationContractFromV4(t *testing.T, w *RoutedDHCPSelectedStoreV3, a *dhcpAuthorityFixtureV3) *dhcpConfigurationFixtureV4 {
	t.Helper()
	subject := w.c.store.state.Subjects[0].ID
	ns, err := w.c.store.namespace(subject, "routed", w.c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Give the fixture's network-selected Running a real verified witness before
	// capturing DHCP Work. This is fixture setup, not active-WAN publication.
	initial := clone(w.c.store.state)
	auditHash, err := w.c.appendAuditLocked(initial.Configuration, "dhcp-contract-fixture", "", "", "system", "fixture", "verified", initial.Generation, w.c.now())
	if err != nil {
		t.Fatal(err)
	}
	initial.Configuration.VerifiedIndex, err = w.c.verifiedInsert(initial.Configuration.VerifiedIndex, 0, v2VerifiedEntry{Revision: initial.Configuration.Running.Hash, Audit: auditHash, Operation: "dhcp-contract-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.c.persistRevisions(*initial.Configuration); err != nil {
		t.Fatal(err)
	}
	if err = w.c.store.publish(initial); err != nil {
		t.Fatal(err)
	}
	hash, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	s := w.c.store
	source := clone(s.state)
	f := &dhcpConfigurationFixtureV4{seed: map[string][]byte{}, store: s}
	before := clone(*source.Configuration)
	when := w.c.now().Add(time.Second)
	id, _ := v2ID("op", source.HighWater+1)
	op := v2Operation{ID: id, Namespace: ns.ID, Subject: subject, Lineage: source.Lineage, Domain: "routed", Sequence: source.HighWater + 1, Expected: source.Generation, Request: v2Request{Kind: OpStage, Config: &before.Firewall.Running.Config}, State: "accepted", Accepted: when, ExecuteBefore: when.Add(900 * time.Second)}
	op.Fingerprint = v2OperationFingerprint(op)
	// Future-format fixture only: authentic low-level R2 admission, no production
	// Admit/publish invocation and no mutation of the active-DHCP guard.
	m := s.reserves
	owner, _ := v2ID("reserve", op.Sequence)
	scope, err := reserveAdmissionScopeV2(s, source, op, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.operationProfile(s, op, owner); err != nil {
		t.Fatal(err)
	}
	claims, err := m.claimOwner(recoveryreserve.OrdinaryV2, owner)
	if err != nil {
		t.Fatal(err)
	}
	capsule := v2ReserveAdmission{Format: v2Format, Version: 1, Scope: scope, Claims: claims}
	raw, _, err := v2Canonical(capsule)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := m.admission.WriteOnce(claims.Admission, raw, scope)
	if err != nil {
		t.Fatal(err)
	}
	op.Reserve = &v2ReserveBundle{Scope: scope, Claims: claims, Admission: binding}
	source.HighWater = op.Sequence
	source.Clock = when
	source.OccupiedOrdinary++
	source.ReservedBytes += v2OperationReserveBytes
	source.ReservedInodes += v2OperationReserveInodes
	source.Namespaces[s.namespaceIndex(subject, ns.ID)].Open = append(source.Namespaces[s.namespaceIndex(subject, ns.ID)].Open, op.ID)
	source.ActiveReserves = append(source.ActiveReserves, v2ActiveReserve{Work: op.ID, Bundle: clone(op.Reserve)})
	if err = s.putOperation(&source, op); err != nil {
		t.Fatal(err)
	}
	if !v2ValidState(source) || !(&v2Store{state: source}).validOperation(op) || m.verifyBundle(s, op.Reserve) != nil {
		t.Fatal("invalid genuine accepted R2 fixture")
	}
	sourceHash := f.object(t, source)
	sel := v2Selection{Format: v2Format, Lineage: source.Lineage, Sequence: s.selection.Sequence + 1, State: sourceHash, Previous: s.selector.Current, Segment: s.selection.Segment + 1}
	selectionHash := f.object(t, sel)
	target, changed, err := routedTargetV2(&v2Store{state: source, objectReader: f.load}, op, before, when, "")
	if err != nil || !changed {
		t.Fatal(err)
	}
	if err = w.c.persistRevisions(target); err != nil {
		t.Fatal(err)
	}
	projected := f.object(t, target)
	generation := source.Generation + 1
	audit := v2CoordinatorAudit{Format: v2Format, Sequence: before.AuditSequence + 1, Previous: before.AuditTip, Operation: op.ID, Subject: op.Subject, Kind: op.Request.Kind, Result: "applied", At: when, Generation: generation, Running: target.Running.Hash, Startup: target.Startup.Hash}
	target.AuditSequence, target.AuditTip = audit.Sequence, f.object(t, audit)
	target.VerifiedIndex, err = w.c.verifiedInsert(target.VerifiedIndex, 0, v2VerifiedEntry{Revision: target.Running.Hash, Audit: target.AuditTip, Operation: op.ID})
	if err != nil {
		t.Fatal(err)
	}
	until := when.Add(30 * 24 * time.Hour)
	op.State, op.Completed, op.RetainUntil = "final", &when, &until
	op.Outcome = &v2Outcome{Code: "applied", Generation: generation, DomainGeneration: domainSnapshotV2(&target, op.Domain).Generation, AuditHash: target.AuditTip, RunningRevision: target.Running.Hash, StartupRevision: target.Startup.Hash, AuditFirst: audit.Sequence, AuditLast: audit.Sequence}
	f.op = op
	f.source = clone(source)
	f.state = clone(source)
	v2Release(&f.state, op)
	f.state.Configuration = &target
	if target.LocalServices.Candidate != nil {
		addFeatureV2(&f.state, v2LocalFeature)
	}
	f.state.Generation = generation
	f.state.Clock = when
	if err = s.putOperation(&f.state, op); err != nil {
		t.Fatal(err)
	}
	f.x = v4RoutedDHCPConfiguration{Version: 4, Lineage: source.Lineage, Kind: "metadata", Impact: "preserve", SourceWork: hash, SourceSelection: SelectionReferenceV2{Selection: selectionHash, Previous: sel.Previous, State: sourceHash, Lineage: source.Lineage, Sequence: sel.Sequence, Generation: source.Generation, WorkHash: hash, Mode: "dhcp-configuration-v4"}, Operation: op.ID, Subject: op.Subject, Namespace: op.Namespace, Fingerprint: op.Fingerprint, Expected: source.Generation, Generation: generation, Before: f.object(t, before), Target: projected}
	transition := f.object(t, f.x)
	receipt := v4RoutedDHCPConfigurationContinuation{Version: 4, Transition: transition, Operation: f.object(t, op), Configuration: f.object(t, target)}
	f.header = &v4RoutedDHCPConfigurationState{Version: 4, Continuation: f.object(t, receipt)}
	return f
}

func TestRoutedDHCPConfigurationV4MetadataRetainsExactWork(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	original := clone(f.state.RoutedDHCP)
	c, err := routedDHCPConfigurationContextV4Read(f.x, f.state, f.load, f.lookup)
	if err != nil || !reflect.DeepEqual(original, f.state.RoutedDHCP) || c.sourceWork.Snapshot.Fact().Owner != (networkexecutor.LeaseOwner{Namespace: c.sourceWork.Snapshot.Identity.Namespace, BootID: c.sourceWork.Snapshot.Identity.BootID, RunID: c.sourceWork.Snapshot.Identity.RunID, PID: c.sourceWork.Snapshot.OwnerPID, StartTicks: c.sourceWork.Snapshot.OwnerStartTicks, Incarnation: c.sourceWork.Snapshot.OwnerIncarnation}) {
		t.Fatal("contract rewrote source or rejected metadata", err)
	}
	if preservesRoutedDHCPV3(c.sourceState, f.state) {
		t.Fatal("contract preparation weakened old generation guard")
	}
	if !errors.Is(f.store.reserveMaintenanceReadyV2(""), ErrRecovery) {
		t.Fatal("contract preparation enabled admission")
	}
}

func TestRoutedDHCPConfigurationV4ConfirmationProjectionBounds(t *testing.T) {
	_, _, _, work, authority := selectedDHCPReaderFixtureV3(t)
	f := dhcpConfigurationContractFromV4(t, work, authority)
	if _, err := routedDHCPConfigurationContinuationV4Read(f.header.Continuation, f.state, f.load); err != nil {
		t.Fatal("full valid fixture must pass before testing conversion bounds", err)
	}
	deadline := f.op.Accepted.Add(120 * time.Second)
	for _, test := range []struct {
		seconds uint64
		want    time.Time
	}{{30, f.op.Accepted.Add(90 * time.Second)}, {120, f.op.Accepted}} {
		got, err := routedDHCPConfigurationProjectionTimeV4(deadline, test.seconds)
		if err != nil || !got.Equal(test.want) {
			t.Fatalf("confirmation boundary %d changed: %v %v", test.seconds, got, err)
		}
	}
	for _, seconds := range []uint64{0, 1, 29, 121, ^uint64(0), 1 << 63, (1<<63-1)/uint64(time.Second) + 1, 1<<55 + 1} {
		// 1<<55 seconds wraps to zero when multiplied by one billion in
		// int64; adding one would falsely project only one second backwards.
		got, err := routedDHCPConfigurationProjectionTimeV4(deadline, seconds)
		if !errors.Is(err, ErrRecovery) || !got.IsZero() {
			t.Fatalf("out-of-range/overflow seconds %d yielded a projection: %v %v", seconds, got, err)
		}
	}
}

func TestRoutedDHCPConfigurationV4AcceptedSourceG1AndR2(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	f.installObjects(t)
	graph := f.graph(t)
	if err := graph.state(f.x.SourceSelection.State, f.source, 1); err != nil {
		t.Fatal("source accepted state did not pass actual G1", err)
	}
	if err := f.store.reserves.verifySelected(&v2Store{state: f.source, objectReader: graph.object}); err != nil {
		t.Fatal("source accepted state did not pass physical R2", err)
	}
}

func TestRoutedDHCPConfigurationV4PublicationRequiresSelectedSourceAndPhysicalReserve(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	f.installObjects(t)
	s := f.store
	if err := s.publish(f.source); err != nil {
		t.Fatal("publish exact accepted fixture", err)
	}
	if s.selector.Current != f.x.SourceSelection.Selection {
		t.Fatal("fixture source differs from actual published selection")
	}
	pending := clone(f.source)
	addFeatureV2(&pending, v4RoutedDHCPConfigurationFeature)
	transition, err := s.object(f.x)
	if err != nil {
		t.Fatal(err)
	}
	pending.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4, Transition: transition}

	foreign := f.x
	altSelection := s.selection
	altSelection.Previous = strings.Repeat("f", 64)
	foreign.SourceSelection.Previous = altSelection.Previous
	foreign.SourceSelection.Selection, err = s.object(altSelection)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := s.object(foreign)
	if err != nil {
		t.Fatal(err)
	}
	invalid := clone(pending)
	invalid.RoutedDHCPConfiguration.Transition = wrong
	original := s.selector
	if err = s.publish(invalid); !errors.Is(err, errV2Unavailable) || s.selector != original || s.blocked {
		t.Fatal("unselected source changed the selector", err)
	}

	reserves := s.reserves
	s.reserves = nil
	err = s.publish(pending)
	s.reserves = reserves
	if !errors.Is(err, errV2Unavailable) || s.selector != original || s.blocked {
		t.Fatal("unverified physical reserve changed the selector", err)
	}
	if err = s.publish(pending); err != nil {
		t.Fatal("publish exact transition", err)
	}
	final := clone(f.state)
	addFeatureV2(&final, v4RoutedDHCPConfigurationFeature)
	final.RoutedDHCPConfiguration = clone(f.header)
	if err = s.publish(final); err != nil {
		t.Fatal("publish exact outcome", err)
	}
	if s.state.Generation != f.x.Generation || !reflect.DeepEqual(s.state.RoutedDHCP, f.source.RoutedDHCP) {
		t.Fatal("publication changed the retained work or selected the wrong generation")
	}
}

// Low-level future-format fixture: no producer/admission path is enabled.
func (f *dhcpConfigurationFixtureV4) installSelected(t *testing.T) v2Selector {
	t.Helper()
	var source v2Selection
	if err := f.load(f.x.SourceSelection.Selection, &source); err != nil {
		t.Fatal(err)
	}
	pending := clone(f.source)
	addFeatureV2(&pending, v4RoutedDHCPConfigurationFeature)
	pending.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4, Transition: f.object(t, f.x)}
	transition := v2Selection{Format: v2Format, Lineage: source.Lineage, Sequence: source.Sequence + 1, Segment: source.Segment + 1, State: f.object(t, pending), Previous: f.x.SourceSelection.Selection}
	transitionHash := f.object(t, transition)
	addFeatureV2(&f.state, v4RoutedDHCPConfigurationFeature)
	f.state.RoutedDHCPConfiguration = clone(f.header)
	if !v2ValidState(pending) || !v2ValidState(f.state) {
		held, heldOK := reserveHeldReservationsV2(f.state)
		t.Fatalf("invalid future fixture state: pending=%t final=%t features=%t config=%t held=%d/%t reserved=%d/%d", v2ValidState(pending), v2ValidState(f.state), validFeaturesV2(f.state), validV2Configuration(f.state.Configuration), held, heldOK, f.state.ReservedBytes, f.state.ReservedInodes)
	}
	final := v2Selection{Format: v2Format, Lineage: source.Lineage, Sequence: transition.Sequence + 1, Segment: transition.Segment + 1, State: f.object(t, f.state), Previous: transitionHash}
	selector := v2Selector{Format: v2Format, Current: f.object(t, final), Previous: transitionHash}
	f.installObjects(t)
	raw, _, err := v2Canonical(selector)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.root.WriteFile("selected.json", raw, 0640); err != nil {
		t.Fatal(err)
	}
	return selector
}

func (f *dhcpConfigurationFixtureV4) installPending(t *testing.T, x v4RoutedDHCPConfiguration) (v2Selector, v2State) {
	t.Helper()
	var source v2Selection
	if err := f.load(f.x.SourceSelection.Selection, &source); err != nil {
		t.Fatal(err)
	}
	pending := clone(f.source)
	addFeatureV2(&pending, v4RoutedDHCPConfigurationFeature)
	pending.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4, Transition: f.object(t, x)}
	selection := v2Selection{Format: v2Format, Lineage: source.Lineage, Sequence: source.Sequence + 1, Segment: source.Segment + 1, State: f.object(t, pending), Previous: f.x.SourceSelection.Selection}
	selector := v2Selector{Format: v2Format, Current: f.object(t, selection), Previous: selection.Previous}
	f.installObjects(t)
	raw, _, err := v2Canonical(selector)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.root.WriteFile("selected.json", raw, 0640); err != nil {
		t.Fatal(err)
	}
	return selector, pending
}

func TestRoutedDHCPConfigurationV4RejectsFictitiousSourceSelection(t *testing.T) {
	_, _, _, work, authority := selectedDHCPReaderFixtureV3(t)
	f := dhcpConfigurationContractFromV4(t, work, authority)
	selector, _ := f.installPending(t, f.x)
	positive := f.graph(t)
	positive.cache = newSelectedReadCacheV2()
	if err := positive.selection(selector.Current, &selector.Previous); err != nil {
		t.Fatal("genuine source edge must pass first", err)
	}
	for _, mode := range []string{"sequence", "previous", "selection"} {
		t.Run(mode, func(t *testing.T) {
			x := clone(f.x)
			var source v2Selection
			if err := f.load(x.SourceSelection.Selection, &source); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "sequence":
				source.Sequence++
			case "previous":
				source.Previous = strings.Repeat("a", 64)
			case "selection":
				source.Segment++
			}
			x.SourceSelection.Selection = f.object(t, source)
			x.SourceSelection.Previous, x.SourceSelection.Sequence = source.Previous, source.Sequence
			selector, pending := f.installPending(t, x)
			lookup := func(subject, id string) (v2Operation, error) {
				return (&v2Store{state: pending, objectReader: f.load}).lookupRetained(subject, id)
			}
			if _, err := routedDHCPConfigurationViewV4Read(pending.RoutedDHCPConfiguration, pending, f.load, lookup, routedDHCPConfigurationHeaderV4); err != nil {
				t.Fatal("negative must remain self-consistent before edge binding", err)
			}
			before := journalFiles(t, f.store.root.Name())
			graph := f.graph(t)
			graph.cache = newSelectedReadCacheV2()
			reader := &v2Store{root: f.store.root, access: f.store.access, readOnly: true, recordReader: graph.storeRecordV2, objectReader: graph.object}
			if err := reader.readSelection(); err == nil {
				t.Fatal("selector accepted fictitious same-state source tuple")
			}
			graph = f.graph(t)
			graph.cache = newSelectedReadCacheV2()
			if err := graph.selection(selector.Current, &selector.Previous); err == nil {
				t.Fatal("G1 accepted fictitious same-state source tuple")
			}
			if !reflect.DeepEqual(before, journalFiles(t, f.store.root.Name())) {
				t.Fatal("read-only source rejection changed files")
			}
		})
	}
}

func TestRoutedDHCPConfigurationV4ModernSelectedG1(t *testing.T) {
	_, _, _, work, authority := selectedDHCPReaderFixtureV3(t)
	f := dhcpConfigurationContractFromV4(t, work, authority)
	selector := f.installSelected(t)
	before := journalFiles(t, f.store.root.Name())
	graph := f.graph(t)
	reader := &v2Store{root: f.store.root, access: f.store.access, readOnly: true, recordReader: graph.storeRecordV2, objectReader: graph.object}
	if err := graph.selection(selector.Current, &selector.Previous); err != nil {
		t.Fatal("modern full G1 rejected typed generation continuation", err)
	}
	if err := reader.readSelection(); err != nil {
		t.Fatal("modern selected reader rejected typed generation continuation", err)
	}
	if err := f.store.reserves.verifySelected(reader); err != nil {
		t.Fatal("modern physical R2 rejected original scope", err)
	}
	if validateRoutedDHCPSelectedV3(reader.state, reader.readObject) == nil || preservesFeaturesV2(f.source, f.state) {
		t.Fatal("read contract weakened legacy generation/publication guard")
	}
	if reader.state.RoutedDHCP.Work != f.x.SourceWork || reader.state.RoutedDHCP.Bundle.Scope.Global != f.source.Generation || reader.state.Generation != f.source.Generation+1 {
		t.Fatal("original Work/scope rewritten")
	}
	if !reflect.DeepEqual(before, journalFiles(t, f.store.root.Name())) {
		t.Fatal("read validation wrote files")
	}
	t.Logf("full G1: objects=%d bytes=%d io_calls=%d depth=%d peak_active_bytes=%d", graph.report.Objects, graph.report.BytesRead, graph.report.IOCalls, graph.report.MaximumDepth, graph.report.PeakActiveBytes)
}

func TestRoutedDHCPConfigurationV4OpaqueReaderSeparatesGenerations(t *testing.T) {
	r, _, _, w, authority := selectedDHCPReaderFixtureV3(t)
	f := dhcpConfigurationContractFromV4(t, w, authority)
	f.installSelected(t)
	selected, err := r.ResolveDHCPConfigurationCurrentV4(context.Background(), f.x.SourceWork)
	if err != nil {
		t.Fatal("independent physical reader", err)
	}
	if selected.OriginalGeneration() != f.source.Generation || selected.CurrentGeneration() != f.source.Generation+1 || selected.CurrentRunning() != f.state.Configuration.Running.Hash || selected.Reference().Mode != "dhcp-configuration-v4" || selected.Reference().WorkHash != f.x.SourceWork || selected.Snapshot().Hash != authority.grant.Snapshot.Hash || selected.Epoch() != authority.grant.Epoch {
		t.Fatal("mixed original source with current selection")
	}
	var original v3RoutedDHCPWork
	if err = f.load(f.x.SourceWork, &original); err != nil || selected.OriginalRunning() != original.Running {
		t.Fatal("original undo revision changed", err)
	}
	if _, err = r.ResolveDHCPCurrentV3(context.Background(), f.x.SourceWork); err == nil {
		t.Fatal("legacy resolver interpreted a continued source as current v3")
	}
	if _, err = r.ResolveDHCPConfigurationCurrentV4(context.Background(), strings.Repeat("f", 64)); err == nil {
		t.Fatal("foreign source accepted")
	}
}

func TestRoutedDHCPConfigurationV4MetadataTransitionAndReceipt(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	nilHeader := func(v2State) *v4RoutedDHCPConfigurationState { return nil }
	pending := clone(f.source)
	addFeatureV2(&pending, v4RoutedDHCPConfigurationFeature)
	addFeatureV2(&f.state, v4RoutedDHCPConfigurationFeature)
	h := &v4RoutedDHCPConfigurationState{Version: 4, Transition: f.object(t, f.x)}
	lookup := func(subject, id string) (v2Operation, error) {
		return (&v2Store{state: pending, objectReader: f.load}).lookupRetained(subject, id)
	}
	if _, err := routedDHCPConfigurationViewV4Read(h, pending, f.load, lookup, nilHeader); err != nil {
		t.Fatal("accepted transition", err)
	}
	if !preservesRoutedDHCPConfigurationReadV4(f.source, nil, pending, h, f.x.SourceSelection, f.load, lookup, nilHeader) {
		t.Fatal("transition source edge rejected")
	}
	if !preservesRoutedDHCPConfigurationReadV4(pending, h, f.state, f.header, SelectionReferenceV2{}, f.load, f.lookup, nilHeader) {
		t.Fatal("metadata final receipt edge rejected")
	}
	if _, err := routedDHCPConfigurationViewV4Read(f.header, f.state, f.load, func(string, string) (v2Operation, error) { return v2Operation{}, ErrRecovery }, nilHeader); err != nil {
		t.Fatal("immutable receipt depended on current circular catalogue", err)
	}
	if preservesRoutedDHCPConfigurationReadV4(f.state, f.header, f.state, nil, SelectionReferenceV2{}, f.load, f.lookup, nilHeader) {
		t.Fatal("header disappeared while original source remained active")
	}
}

func TestRoutedDHCPConfigurationV4RejectsForgedContext(t *testing.T) {
	for _, mode := range []string{"lineage", "expected", "generation", "selection", "work", "namespace", "fingerprint", "missing_audit", "forged_index", "audit_previous", "replacement", "mixed", "missing_operation", "unselected_operation"} {
		t.Run(mode, func(t *testing.T) {
			f := dhcpConfigurationContractFixtureV4(t)
			switch mode {
			case "lineage":
				f.x.Lineage = "foreign"
			case "expected":
				f.x.Expected++
			case "generation":
				f.state.Generation++
			case "selection":
				f.x.SourceSelection.Sequence++
			case "work":
				f.x.SourceWork = strings.Repeat("f", 64)
			case "namespace":
				f.op.Namespace = "foreign"
				f.op.Fingerprint = v2OperationFingerprint(f.op)
				f.x.Fingerprint = f.op.Fingerprint
			case "fingerprint":
				f.op.Fingerprint = strings.Repeat("f", 64)
				f.x.Operation = f.object(t, f.op)
			case "missing_audit":
				delete(f.seed, f.op.Outcome.AuditHash)
			case "forged_index":
				f.state.Configuration.VerifiedIndex = strings.Repeat("a", 64)
			case "audit_previous":
				var audit v2CoordinatorAudit
				if err := f.load(f.op.Outcome.AuditHash, &audit); err != nil {
					t.Fatal(err)
				}
				audit.Previous = strings.Repeat("a", 64)
				f.op.Outcome.AuditHash = f.object(t, audit)
				f.state.Configuration.AuditTip = f.op.Outcome.AuditHash
			case "replacement":
				f.x.Kind = "grouped"
				f.x.Impact = "replace"
				f.x.Group = &v4RoutedDHCPConfigurationGroup{Work: strings.Repeat("a", 64), Side: "target"}
				f.x.Replacement = &v4RoutedDHCPConfigurationReplacement{Acquisition: strings.Repeat("b", 64)}
			case "mixed":
				f.x.Group = &v4RoutedDHCPConfigurationGroup{Work: strings.Repeat("a", 64), Side: "target"}
			case "missing_operation":
				f.x.Operation = "missing"
			case "unselected_operation":
				f.op.ID = "foreign"
			}
			var receipt v4RoutedDHCPConfigurationContinuation
			if err := f.load(f.header.Continuation, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Transition = f.object(t, f.x)
			receipt.Operation = f.object(t, f.op)
			receipt.Configuration = f.object(t, *f.state.Configuration)
			f.header.Continuation = f.object(t, receipt)
			addFeatureV2(&f.state, v4RoutedDHCPConfigurationFeature)
			if _, err := routedDHCPConfigurationViewV4Read(f.header, f.state, f.load, f.lookup, func(v2State) *v4RoutedDHCPConfigurationState { return nil }); err == nil {
				t.Fatal("forged continuation accepted")
			}

		})
	}
}

func TestRoutedDHCPConfigurationV4RealGraphRejectsAmbiguousRecords(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	valid, validHash, err := v2Canonical(f.x)
	if err != nil {
		t.Fatal(err)
	}
	pending := clone(f.source)
	addFeatureV2(&pending, v4RoutedDHCPConfigurationFeature)
	pending.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4, Transition: validHash}
	f.installObjects(t)
	if err = f.graph(t).state("positive", pending, 1); err != nil {
		t.Fatal("valid complete graph must pass first", err)
	}
	mixed := clone(f.x)
	mixed.Group = &v4RoutedDHCPConfigurationGroup{Work: strings.Repeat("a", 64), Side: "target"}
	mixedRaw, _ := json.Marshal(mixed)
	for name, raw := range map[string][]byte{
		"alias":     []byte(strings.Replace(string(valid), `"version":4`, `"Version":4`, 1)),
		"duplicate": []byte(strings.Replace(string(valid), `"version":4`, `"version":4,"version":4`, 1)),
		"null":      []byte(strings.Replace(string(valid), `"version":4`, `"version":4,"group":null`, 1)),
		"unknown":   []byte(strings.Replace(string(valid), `"version":4`, `"version":4,"unknown":true`, 1)),
		"mixed":     mixedRaw,
	} {
		t.Run(name, func(t *testing.T) {
			hash := checkpointDigest(raw)
			filename, _ := v2ObjectName(hash)
			if err := f.store.root.WriteFile(filename, raw, 0640); err != nil {
				t.Fatal(err)
			}
			state := clone(pending)
			state.RoutedDHCPConfiguration.Transition = hash
			before := journalFiles(t, f.store.root.Name())
			if err := f.graph(t).state("current", state, 1); err == nil {
				t.Fatal("actual G1 accepted mutated record with valid dependencies")
			}
			if !reflect.DeepEqual(before, journalFiles(t, f.store.root.Name())) {
				t.Fatal("read-only rejection changed files")
			}
		})
	}
}

func TestRoutedDHCPConfigurationV4StrictDecoder(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	raw, _ := json.Marshal(f.x)
	if _, err := decodeRoutedDHCPConfigurationV4(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), []byte("{}")...),
		[]byte(strings.Replace(string(raw), `"version":4`, `"version":4,"version":4`, 1)),
		[]byte(strings.Replace(string(raw), `"version":4`, `"Version":4`, 1)),
		[]byte(strings.Replace(string(raw), `"version":4`, `"version":4,"group":null`, 1)),
		[]byte(strings.Replace(string(raw), `"version":4`, `"version":4,"unknown":true`, 1)),
		[]byte(strings.Repeat(" ", v4RoutedDHCPConfigurationLimit+1)),
	} {
		if _, err := decodeRoutedDHCPConfigurationV4(bad); err == nil {
			t.Fatal("ambiguous control document accepted")
		}
	}
}

func TestRoutedDHCPConfigurationV4FullNetworkImpact(t *testing.T) {
	f := dhcpConfigurationContractFixtureV4(t)
	c, err := routedDHCPConfigurationContextV4Read(f.x, f.state, f.load, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if impact, err := routedDHCPConfigurationImpactV4(c.sourceWork, c.before, c.target); err != nil || impact != "preserve" {
		t.Fatal(impact, err)
	}
	for name, change := range map[string]func(*networkplan.Config){
		"route": func(n *networkplan.Config) { n.DefaultRoute.Metric++ },
		"lan":   func(n *networkplan.Config) { n.Interfaces[0].IPv4.Address = "198.18.1.1/24" },
		"dns":   func(n *networkplan.Config) { n.DNS = networkplan.DNS{Mode: "static", Servers: []string{"198.19.0.53"}} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(c.target)
			n := changed.Firewall.Running.Config.Routed.Network.Config
			change(&n)
			r, err := networkplan.Canonical(n)
			if err != nil {
				t.Fatal(err)
			}
			fw := clone(changed.Firewall.Running.Config)
			fw.Routed.Network = r
			changed.Firewall.Running, err = CanonicalRouted(fw)
			if err != nil {
				t.Fatal(err)
			}
			if err = changed.refresh(); err != nil {
				t.Fatal(err)
			}
			if impact, err := routedDHCPConfigurationImpactV4(c.sourceWork, c.before, changed); err != nil || impact != "replace" {
				t.Fatal("full network change mislabeled preserve", impact, err)
			}
			x, st := clone(f.x), clone(f.state)
			st.Configuration = &changed
			x.Target = f.object(t, changed)
			if _, err = routedDHCPConfigurationContextV4Read(x, st, f.load, f.lookup); err == nil {
				t.Fatal("false preserve accepted")
			}
		})
	}
}
