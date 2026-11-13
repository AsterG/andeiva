//go:build linux

package previewruntime

import (
	"context"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

// Only this read-only subset is available to a cold-migration source verifier.
// It cannot install a table, create a listener, or authorize the new namespace.
type routedMigrationKernelV3 interface {
	Observe(context.Context, routedactivation.Table) ([]byte, bool, error)
}

func verifyRoutedMigrationSourceV3(ctx context.Context, kernel routedMigrationKernelV3, expected [2]configpoc.LegacyFingerprintV2, firewall, local configpoc.Revision) error {
	if ctx == nil || ctx.Err() != nil || kernel == nil || expected[0].Domain != "firewall" || expected[1].Domain != "local_services" {
		return ErrUnavailable
	}
	fw, err := configpoc.Canonical(firewall.Config)
	if err != nil || fw.Hash != firewall.Hash || fw.Config.SchemaVersion != 4 {
		return ErrConfiguration
	}
	ls, err := configpoc.Canonical(local.Config)
	if err != nil || ls.Hash != local.Hash || ls.Config.SchemaVersion != 3 || ls.Config.LocalServices == nil || len(ls.Config.Rules) != 0 || len(ls.Config.LocalServices.Services) != 0 {
		return ErrConfiguration
	}
	// This first migration profile has no local-service module declarations.
	// Foreign listeners are neither attributed to ANDEIVA nor silently removed.
	// The managed local table must actually be absent, not merely unreadable.
	data, exists, err := kernel.Observe(ctx, routedactivation.LegacyTable)
	if err != nil || !exists {
		return ErrUnavailable
	}
	if _, err = firewallnft.VerifyObservation(data, fw); err != nil {
		return ErrUnavailable
	}
	for _, table := range []routedactivation.Table{routedactivation.LocalTable, routedactivation.RoutedTable} {
		_, exists, err = kernel.Observe(ctx, table)
		if err != nil || exists {
			return ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	// A second semantic read detects changes during the auxiliary observations.
	// Source journal locks remain held by the caller through selected publication.
	data, exists, err = kernel.Observe(ctx, routedactivation.LegacyTable)
	if err != nil || !exists {
		return ErrUnavailable
	}
	if _, err = firewallnft.VerifyObservation(data, fw); err != nil {
		return ErrUnavailable
	}
	return nil
}
