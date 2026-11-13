package configpoc

import (
	"context"
	"errors"
	"os"
	"time"
)

// MigrationProvenanceV3 is trusted, read-only installer metadata. It exposes
// neither protected receipts nor a new administrative transport or authority.
type MigrationProvenanceV3 struct {
	Selection          SelectionReferenceV2
	Sources            [2]LegacyFingerprintV2
	LocalInitializedAt time.Time
	LocalRevision      Revision
}

// MigrationProvenanceV3 reads the selected migration image, never a proposed
// directory or caller-supplied snapshot. Full-history integrity and final
// descriptor/selector/pool revalidation remain mandatory.
func (r *RoutedSelectionReaderV2) MigrationProvenanceV3(ctx context.Context) (out MigrationProvenanceV3, result error) {
	if r == nil || ctx == nil {
		return out, ErrInvalid
	}
	if r.options.Policy != SelectionFullHistoryV2 {
		return out, ErrDenied
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	view, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if view.graph.closeSelectedV2() != nil {
			out = MigrationProvenanceV3{}
			result = ErrRecovery
		}
	}()
	out, err = migrationProvenanceFromStateV3(view.store.state, view.store.readObject)
	if err != nil {
		return MigrationProvenanceV3{}, err
	}
	out.Selection = view.ref
	if err = r.revalidate(ctx, view); err != nil {
		return MigrationProvenanceV3{}, err
	}
	return out, nil
}

func migrationProvenanceFromStateV3(state v2State, read func(string, any) error) (MigrationProvenanceV3, error) {
	var out MigrationProvenanceV3
	if read == nil || state.Migration == "" || validateMigrationReadV2(state, read) != nil {
		return out, ErrRecovery
	}
	var migration v2Migration
	if read(state.Migration, &migration) != nil || migration.Firewall.Domain != "firewall" || migration.LocalServices.Domain != "local_services" || len(migration.LocalServices.Records) != 1 || migration.LocalServices.Sequence != 1 || migration.LocalServices.Projection != 1 {
		return out, ErrRecovery
	}
	image := migration.LocalServices
	local, err := Canonical(image.Snapshot.Running.Config)
	if err != nil || local.Hash != image.Snapshot.Running.Hash || local.Config.SchemaVersion != 3 || local.Config.LocalServices == nil || len(local.Config.Rules) != 0 || len(local.Config.LocalServices.Services) != 0 {
		return out, ErrRecovery
	}
	var record struct {
		Format string `json:"format"`
		Bytes  []byte `json:"bytes"`
	}
	if read(image.Records[0], &record) != nil || record.Format != v2Format {
		return out, ErrRecovery
	}
	initial, err := decodeRecord(record.Bytes, 1, "", "")
	if err != nil || initial.Audit.Operation != "initialize" || initial.Audit.Actor != "system" || initial.Audit.Surface != API || initial.Audit.Result != "ok" || initial.Audit.At.IsZero() || initial.Audit.RunningHash != local.Hash || initial.State.Snapshot.Generation != 1 || initial.State.Snapshot.Running.Hash != local.Hash || initial.State.Snapshot.Startup.Hash != local.Hash || initial.State.Snapshot.LastGood.Hash != local.Hash || initial.State.Intent != nil || initial.State.Snapshot.Candidate != nil || initial.State.Snapshot.Pending != nil || initial.State.Snapshot.RecoveryRequired || len(initial.State.Receipts) != 0 || len(initial.State.Snapshot.Revoked) != 0 {
		return out, ErrRecovery
	}
	out.Sources = [2]LegacyFingerprintV2{fingerprintLegacyV2(migration.Firewall), fingerprintLegacyV2(image)}
	out.LocalInitializedAt = initial.Audit.At.UTC()
	out.LocalRevision = local
	return out, nil
}

// WithLegacyFingerprintV3 is an installer-only read scope. The visitor must
// honor ctx and must not reopen this source. The original legacy lock and
// validators remain authoritative throughout the callback and final recheck.
func WithLegacyFingerprintV3(ctx context.Context, area *os.Root, domain string, visit func(context.Context, LegacyFingerprintV2) error) (result error) {
	if ctx == nil || area == nil || visit == nil || (domain != "firewall" && domain != "local_services") {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	lock, err := lockLegacyV2(area)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	image, err := inspectLegacyV2(area, domain, nil)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	expected := fingerprintLegacyV2(image)
	visited := visit(ctx, expected)
	current, readErr := inspectLegacyV2(area, domain, nil)
	if readErr != nil {
		return errors.Join(visited, readErr)
	}
	if fingerprintLegacyV2(current) != expected {
		return errors.Join(visited, ErrConflict)
	}
	return errors.Join(visited, ctx.Err())
}
