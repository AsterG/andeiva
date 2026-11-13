//go:build linux

package previewruntime

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// RoutedLocalOriginV3 records creation of a new inactive domain. It is private
// installer provenance, not selected policy, a physical readback or an API DTO.
type RoutedLocalOriginV3 struct {
	Version   int                           `json:"version"`
	Kind      string                        `json:"kind"`
	CreatedAt time.Time                     `json:"created_at"`
	Source    configpoc.LegacyFingerprintV2 `json:"source"`
	Revision  string                        `json:"revision"`
}

func cloneRoutedLocalOriginV3(value *RoutedLocalOriginV3) *RoutedLocalOriginV3 {
	if value == nil {
		return nil
	}
	detached := *value
	return &detached
}
func validateRoutedLocalOriginV3(value *RoutedLocalOriginV3) error {
	if value == nil || value.Version != 1 || value.Kind != "new-inactive-v1" || value.CreatedAt.IsZero() || value.Source.Domain != "local_services" || !validHex(value.Source.Source, 32) || !validHex(value.Source.Tip, 32) || !validHex(value.Source.ReceiptIndex, 32) || value.Source.Sequence != 1 || value.Source.Projection != 1 || !validHex(value.Revision, 32) {
		return ErrIdentity
	}
	return nil
}
func matchRoutedLocalOriginV3(expected *RoutedLocalOriginV3, actual configpoc.MigrationProvenanceV3) error {
	if validateRoutedLocalOriginV3(expected) != nil || actual.Sources[1] != expected.Source || actual.LocalRevision.Hash != expected.Revision || !actual.LocalInitializedAt.Equal(expected.CreatedAt) {
		return ErrIdentity
	}
	return nil
}

func verifySelectedRoutedLocalOriginV3(ctx context.Context, reader *configpoc.RoutedSelectionReaderV2, expected *RoutedLocalOriginV3) error {
	if ctx == nil || ctx.Err() != nil || reader == nil || validateRoutedLocalOriginV3(expected) != nil {
		return ErrIdentity
	}
	actual, err := reader.MigrationProvenanceV3(ctx)
	if err != nil || matchRoutedLocalOriginV3(expected, actual) != nil {
		return ErrIdentity
	}
	return nil
}
