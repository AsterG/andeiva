//go:build linux

package main

import (
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/previewruntime"
)

func TestDHCPOwnerRolesRejectAdditionalArguments(t *testing.T) {
	for _, role := range []string{previewruntime.RoutedDHCPOwnerRoleV3, previewruntime.RoutedDHCPDeferredOwnerRoleV4, previewruntime.RoutedSelectedPreflightRoleV4} {
		t.Run(role, func(t *testing.T) {
			if err := run([]string{role, "--config", "/untrusted"}); !errors.Is(err, previewruntime.ErrConfiguration) {
				t.Fatalf("role accepted caller configuration: %v", err)
			}
		})
	}
}
