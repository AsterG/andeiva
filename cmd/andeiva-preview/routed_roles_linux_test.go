//go:build linux

package main

import (
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/previewruntime"
)

func TestRoutedRolesRejectCallerConfiguration(t *testing.T) {
	for _, role := range []string{previewruntime.RoutedHelperRoleV3, previewruntime.RoutedAPIRoleV3, previewruntime.RoutedDHCPServerRoleV2} {
		if err := run([]string{role, "--config", "/caller/chosen.json"}); !errors.Is(err, previewruntime.ErrConfiguration) {
			t.Fatal("child role accepted caller configuration", role, err)
		}
	}
}

func TestRoutedDHCPServerRolesRejectUnsealedInvocation(t *testing.T) {
	for _, role := range []string{previewruntime.RoutedDHCPServerRoleV1, previewruntime.RoutedDHCPServerRoleV2} {
		if err := run([]string{role}); !errors.Is(err, previewruntime.ErrIdentity) {
			t.Fatal("child role accepted without a supported sealed bootstrap", role, err)
		}
	}
}
