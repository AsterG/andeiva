package configpoc

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

const routedBootMarkReservationFeatureV1 = "configuration.routed-boot-mark-reservation.v1"

type routedBootMarkCursorV1 struct {
	Boot        v2BootID `json:"boot_id"`
	Work        string   `json:"work"`
	Source      string   `json:"source_selection"`
	BaseIssued  uint32   `json:"base_issued"`
	Issued      uint32   `json:"issued"`
	Reservation string   `json:"reservation"`
}

type routedBootMarkReservationV1 struct {
	Operation  string                                 `json:"operation_id"`
	Work       string                                 `json:"work"`
	Source     string                                 `json:"source_selection"`
	Scope      networkexecutor.OwnedNamespaceIdentity `json:"scope"`
	Before     string                                 `json:"before"`
	Target     string                                 `json:"target"`
	BaseIssued uint32                                 `json:"base_issued"`
	Prior      *routedmodel.AdmissionMarks            `json:"prior,omitempty"`
	Applied    routedmodel.AdmissionMarks             `json:"applied"`
	Restored   routedmodel.AdmissionMarks             `json:"restored"`
}

// RoutedBootMarkPlanV1 supplies the exact persisted assignments to trusted
// helper assembly. The selected operation must bind this reservation hash.
type RoutedBootMarkPlanV1 struct {
	Prior      *routedmodel.AdmissionMarks
	Applied    routedmodel.AdmissionMarks
	Restored   routedmodel.AdmissionMarks
	BaseIssued uint32
}

func selectedRoutedBootMarksForApplyV1(s *v2Store, plan RoutedSelectedPlanV1, reference SelectionReferenceV2) (RoutedBootMarkPlanV1, error) {
	state := s.state
	if reference.Mode != "intent" || reference.WorkHash != plan.Reference().Work ||
		state.RoutedBootMarks == nil || state.RoutedDHCPConfiguration == nil ||
		state.RoutedDHCPConfiguration.Transition == "" || state.Configuration == nil {
		return RoutedBootMarkPlanV1{}, ErrRecovery
	}
	view, err := routedDHCPConfigurationViewV4Read(state.RoutedDHCPConfiguration, state, s.readObject, s.lookupRetained, routedDHCPConfigurationHeaderV4)
	if err != nil || view.pending == nil || view.pending.operation.State != "pending" {
		return RoutedBootMarkPlanV1{}, ErrRecovery
	}
	transition := view.pending.transition
	group := transition.Group
	if group == nil || group.Side != "target" || group.Work != reference.WorkHash ||
		transition.Operation != plan.Transition().Operation || group.MarkReservation != state.RoutedBootMarks.Reservation {
		return RoutedBootMarkPlanV1{}, ErrRecovery
	}
	record, err := loadRoutedBootMarkReservationV1(state.RoutedBootMarks, state.Lineage, s.readObject)
	if err != nil || record.Scope != plan.Scope().Identity || record.Work != transition.SourceWork ||
		record.Operation != transition.Operation {
		return RoutedBootMarkPlanV1{}, ErrRecovery
	}
	return RoutedBootMarkPlanV1{Prior: record.Prior, Applied: record.Applied, Restored: record.Restored, BaseIssued: record.BaseIssued}, nil
}

// ResolveBootMarkPlanV1 releases no allocation before independently validating
// the selector, physical reserves and exact original gateway ownership.
func (r *RoutedSelectionReaderV2) ResolveBootMarkPlanV1(ctx context.Context, work, reservation, operation string) (out RoutedBootMarkPlanV1, result error) {
	if r == nil || !validHash(work) || !validHash(reservation) || !clientAuditIDV2(operation) {
		return out, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.readCandidateWithGateV2(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedBootMarkPlanV1{}
			result = ErrRecovery
		}
	}()
	st := v.store.state
	if st.RoutedBootMarks == nil || st.RoutedBootMarks.Reservation != reservation ||
		st.RoutedDHCP == nil || st.RoutedDHCP.Phase != "applied" || st.RoutedDHCP.Work != work {
		return out, ErrRecovery
	}
	record, err := loadRoutedBootMarkReservationV1(st.RoutedBootMarks, st.Lineage, v.store.readObject)
	if err != nil || record.Work != work || record.Scope != r.options.Identity || record.Operation != operation {
		return out, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return out, err
	}
	return RoutedBootMarkPlanV1{Prior: record.Prior, Applied: record.Applied, Restored: record.Restored, BaseIssued: record.BaseIssued}, nil
}

func validRoutedBootMarkCursorV1(st v2State) bool {
	cursor := st.RoutedBootMarks
	if cursor == nil {
		return !hasFeatureV2(st, routedBootMarkReservationFeatureV1)
	}
	return hasFeatureV2(st, routedBootMarkReservationFeatureV1) && hasFeatureV2(st, v3RoutedDHCPFeature) &&
		validBootIDV2(cursor.Boot) && validHash(cursor.Work) && validHash(cursor.Source) && cursor.BaseIssued <= cursor.Issued &&
		cursor.Issued <= routedmodel.MaxAdmissionMarks && validHash(cursor.Reservation)
}

func validRoutedBootMarkSourceV1(previous, next v2State, source string) bool {
	n, p := next.RoutedBootMarks, previous.RoutedBootMarks
	return n == nil || p != nil && *p == *n || n.Source == source
}

func preservesRoutedBootMarkCursorV1(previous, next v2State) bool {
	p, n := previous.RoutedBootMarks, next.RoutedBootMarks
	if p == nil && n == nil || p != nil && n != nil && *p == *n {
		return true
	}
	if n == nil || previous.RoutedDHCP == nil || previous.RoutedDHCP.Phase != "applied" ||
		previous.RoutedDHCP.Work != n.Work || !reflect.DeepEqual(previous.RoutedDHCP, next.RoutedDHCP) {
		return false
	}
	if p == nil {
		return n.BaseIssued == 0
	}
	// Same-boot recovery and compensation retain the watermark even if the
	// DHCP Work goes away. No reset is admitted through this publication.
	return n.Boot == p.Boot && n.BaseIssued == p.Issued && n.Issued >= p.Issued
}

func loadRoutedBootMarkReservationV1(cursor *routedBootMarkCursorV1, lineage string, load func(string, any) error) (routedBootMarkReservationV1, error) {
	var record routedBootMarkReservationV1
	if cursor == nil || load(cursor.Reservation, &record) != nil || record.Work != cursor.Work || !clientAuditIDV2(record.Operation) ||
		record.Source != cursor.Source || !validRoutedIdentityV1(record.Scope) ||
		record.Scope.BootID != string(cursor.Boot) || record.Restored.Issued != cursor.Issued ||
		record.Applied.Boot != string(cursor.Boot) || record.Restored.Boot != string(cursor.Boot) ||
		record.BaseIssued != cursor.BaseIssued || record.BaseIssued > cursor.Issued {
		return record, ErrRecovery
	}
	work, err := loadRoutedDHCPWorkV3(record.Work, lineage, load)
	var before, target routedmodel.Revision
	if err != nil || work.Snapshot.Identity != record.Scope ||
		load(record.Before, &before) != nil || load(record.Target, &target) != nil {
		return record, ErrRecovery
	}
	applied, _, err := routedmodel.ReserveAdmissionMarks(string(cursor.Boot), record.BaseIssued, record.Prior, before, target)
	if err != nil || !sameRoutedAdmissionMarksV1(applied, record.Applied) ||
		routedmodel.VerifyAdmissionChange(applied, record.Restored, applied.Issued, target, before) != nil {
		return record, ErrRecovery
	}
	return record, nil
}

func sameRoutedAdmissionMarksV1(a, b routedmodel.AdmissionMarks) bool {
	return a.Boot == b.Boot && a.Revision == b.Revision && a.Issued == b.Issued && slices.Equal(a.Bindings, b.Bindings)
}

func validReservedRoutedGroupMarksV1(source v2State, reservation, operation string, scope networkexecutor.OwnedNamespaceIdentity, before, target v2Configuration, load func(string, any) error) bool {
	if source.RoutedDHCP == nil || source.RoutedBootMarks == nil || source.RoutedBootMarks.Reservation != reservation ||
		before.Firewall.Running.Config.Routed == nil || target.Firewall.Running.Config.Routed == nil {
		return false
	}
	record, err := loadRoutedBootMarkReservationV1(source.RoutedBootMarks, source.Lineage, load)
	if err != nil || record.Scope != scope || record.Work != source.RoutedDHCP.Work || record.Operation != operation {
		return false
	}
	prior, err := routedmodel.Canonical(*before.Firewall.Running.Config.Routed)
	if err != nil || record.Restored.Revision != prior.Hash {
		return false
	}
	desired, err := routedmodel.Canonical(*target.Firewall.Running.Config.Routed)
	return err == nil && record.Applied.Revision == desired.Hash
}

// reserveRoutedBootMarksLocked burns target and compensation marks in the
// protected selection before the helper can observe their reservation.
// The caller holds the existing writer lock and supplies the authenticated
// gateway identity and its verified strict source policy.
func (s *v2Store) reserveRoutedBootMarksLocked(identity networkexecutor.OwnedNamespaceIdentity, operation string, prior *routedmodel.AdmissionMarks, before, target routedmodel.Revision) (applied, restored routedmodel.AdmissionMarks, requiresClosure bool, err error) {
	if s.state.RoutedDHCP == nil || s.state.RoutedDHCP.Phase != "applied" || s.reserves == nil || !clientAuditIDV2(operation) {
		return applied, restored, false, ErrRecovery
	}
	work, err := loadRoutedDHCPWorkV3(s.state.RoutedDHCP.Work, s.state.Lineage, s.readObject)
	if err != nil || work.Snapshot.Identity != identity || !validRoutedIdentityV1(identity) ||
		s.reserves.verifySelected(s) != nil {
		return applied, restored, false, ErrRecovery
	}
	if s.state.Configuration == nil || s.state.Configuration.Intent != nil || s.state.Configuration.RecoveryRequired ||
		s.state.Configuration.Pending != nil || s.state.Configuration.Firewall.Running.Config.Routed == nil {
		return applied, restored, false, ErrRecovery
	}
	current, err := routedmodel.Canonical(*s.state.Configuration.Firewall.Running.Config.Routed)
	if err != nil || current.Hash != before.Hash {
		return applied, restored, false, ErrRecovery
	}
	boot := v2BootID(identity.BootID)
	var issued uint32
	if cursor := s.state.RoutedBootMarks; cursor != nil {
		if cursor.Boot != boot {
			return applied, restored, false, ErrRecovery
		}
		issued = cursor.Issued
	}
	applied, requiresClosure, err = routedmodel.ReserveAdmissionMarks(string(boot), issued, prior, before, target)
	var restoreClosure bool
	if err == nil {
		restored, restoreClosure, err = routedmodel.ReserveAdmissionMarks(string(boot), applied.Issued, &applied, target, before)
	}
	if err != nil {
		if errors.Is(err, routedmodel.ErrAdmissionMarksExhausted) {
			err = errV2Limited
		}
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	beforeHash, err := s.object(before)
	if err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	targetHash, err := s.object(target)
	if err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	reservation, err := s.object(routedBootMarkReservationV1{Operation: operation, Work: s.state.RoutedDHCP.Work, Source: s.selector.Current, Scope: identity,
		Before: beforeHash, Target: targetHash, BaseIssued: issued, Prior: prior, Applied: applied, Restored: restored})
	if err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	next := clone(s.state)
	next.RoutedBootMarks = &routedBootMarkCursorV1{Boot: boot, Work: s.state.RoutedDHCP.Work,
		Source: s.selector.Current, BaseIssued: issued, Issued: restored.Issued, Reservation: reservation}
	addFeatureV2(&next, routedBootMarkReservationFeatureV1)
	if err = s.publish(next); err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	// Adoption with no strict source requires closure even when every filter
	// is unchanged. Never hand a legacy source to the atomic path.
	return applied, restored, requiresClosure || restoreClosure || prior == nil, nil
}
