package configpoc

import (
	"context"
	"errors"
	"os"
)

// WithLegacySnapshotV3 lends a detached validated snapshot to the trusted
// installer while retaining the original source lock through its callback.
// The visitor must honor ctx and must not reopen this source.
func WithLegacySnapshotV3(ctx context.Context, area *os.Root, domain string, visit func(context.Context, LegacyFingerprintV2, Snapshot) error) (result error) {
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
	visited := visit(ctx, expected, clone(image.Snapshot))
	current, readErr := inspectLegacyV2(area, domain, nil)
	if readErr != nil {
		return errors.Join(visited, readErr)
	}
	if fingerprintLegacyV2(current) != expected {
		return errors.Join(visited, ErrConflict)
	}
	return errors.Join(visited, ctx.Err())
}
