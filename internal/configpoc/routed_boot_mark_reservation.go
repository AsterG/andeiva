package configpoc

import (
	"context"
	"reflect"
	"slices"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

const routedBootMarkReservationFeatureV1 = "configuration.routed-boot-mark-reservation.v1"

type routedBootMarkCursorV1 struct {
	Boot        v2BootID `json:"boot_id"`
	BaseIssued  uint32   `json:"base_issued"`
	Issued      uint32   `json:"issued"`
	Reservation string   `json:"reservation"`
}

type routedBootMarkReservationV1 struct {
	Work       string                                 `json:"work"`
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
	Applied  routedmodel.AdmissionMarks
	Restored routedmodel.AdmissionMarks
}

// ResolveBootMarkPlanV1 releases no allocation before independently validating
// the selector, physical reserves and exact original gateway ownership.
func (r *RoutedSelectionReaderV2) ResolveBootMarkPlanV1(ctx context.Context, work, reservation string) (out RoutedBootMarkPlanV1, result error) {
	if r == nil || !validHash(work) || !validHash(reservation) {
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
	if err != nil || record.Work != work || record.Scope != r.options.Identity {
		return out, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return out, err
	}
	return RoutedBootMarkPlanV1{Applied: record.Applied, Restored: record.Restored}, nil
}

func validRoutedBootMarkCursorV1(st v2State) bool {
	cursor := st.RoutedBootMarks
	if cursor == nil {
		return !hasFeatureV2(st, routedBootMarkReservationFeatureV1)
	}
	return hasFeatureV2(st, routedBootMarkReservationFeatureV1) && hasFeatureV2(st, v3RoutedDHCPFeature) &&
		validBootIDV2(cursor.Boot) && cursor.BaseIssued < cursor.Issued && cursor.Issued <= routedmodel.MaxAdmissionMarks && validHash(cursor.Reservation)
}

func preservesRoutedBootMarkCursorV1(previous, next v2State) bool {
	p, n := previous.RoutedBootMarks, next.RoutedBootMarks
	if p == nil && n == nil || p != nil && n != nil && *p == *n {
		return true
	}
	if n == nil || previous.RoutedDHCP == nil || previous.RoutedDHCP.Phase != "applied" ||
		!reflect.DeepEqual(previous.RoutedDHCP, next.RoutedDHCP) {
		return false
	}
	if p == nil {
		return n.BaseIssued == 0
	}
	// Same-boot recovery and compensation retain the watermark even if the
	// DHCP Work goes away. No reset is admitted through this publication.
	return n.Boot == p.Boot && n.BaseIssued == p.Issued && n.Issued > p.Issued
}

func loadRoutedBootMarkReservationV1(cursor *routedBootMarkCursorV1, lineage string, load func(string, any) error) (routedBootMarkReservationV1, error) {
	var record routedBootMarkReservationV1
	if cursor == nil || load(cursor.Reservation, &record) != nil || !validRoutedIdentityV1(record.Scope) ||
		record.Scope.BootID != string(cursor.Boot) || record.Restored.Issued != cursor.Issued ||
		record.Applied.Boot != string(cursor.Boot) || record.Restored.Boot != string(cursor.Boot) ||
		record.BaseIssued != cursor.BaseIssued || record.BaseIssued >= cursor.Issued {
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

// reserveRoutedBootMarksLocked burns target and compensation marks in the
// protected selection before the helper can observe their reservation.
// The caller holds the existing writer lock and supplies the authenticated
// gateway identity and its verified strict source policy.
func (s *v2Store) reserveRoutedBootMarksLocked(identity networkexecutor.OwnedNamespaceIdentity, prior *routedmodel.AdmissionMarks, before, target routedmodel.Revision) (applied, restored routedmodel.AdmissionMarks, requiresClosure bool, err error) {
	if s.state.RoutedDHCP == nil || s.state.RoutedDHCP.Phase != "applied" || s.reserves == nil {
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
	if err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	var restoreClosure bool
	restored, restoreClosure, err = routedmodel.ReserveAdmissionMarks(string(boot), applied.Issued, &applied, target, before)
	if err != nil {
		return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
	}
	if restored.Issued != issued {
		beforeHash, e := s.object(before)
		if e != nil {
			return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, e
		}
		targetHash, e := s.object(target)
		if e != nil {
			return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, e
		}
		reservation, e := s.object(routedBootMarkReservationV1{Work: s.state.RoutedDHCP.Work, Scope: identity,
			Before: beforeHash, Target: targetHash, BaseIssued: issued, Prior: prior, Applied: applied, Restored: restored})
		if e != nil {
			return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, e
		}
		next := clone(s.state)
		next.RoutedBootMarks = &routedBootMarkCursorV1{Boot: boot, BaseIssued: issued, Issued: restored.Issued, Reservation: reservation}
		addFeatureV2(&next, routedBootMarkReservationFeatureV1)
		if err = s.publish(next); err != nil {
			return routedmodel.AdmissionMarks{}, routedmodel.AdmissionMarks{}, false, err
		}
	}
	// Adoption with no strict source requires closure even when every filter
	// is unchanged. Never hand a legacy source to the atomic path.
	return applied, restored, requiresClosure || restoreClosure || prior == nil, nil
}
