//go:build linux

package main

import (
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/previewruntime"
)

func TestIntegrityPrepareRoleRequiresTrustedLaunch(t *testing.T) {
	for _, key := range []string{"ANDEIVA_PREPARE_UID", "ANDEIVA_PREPARE_GID", "ANDEIVA_PREPARE_PARENT"} {
		t.Setenv(key, "")
	}
	if err := run([]string{previewruntime.RoutedIntegrityPrepareRoleV3}); !errors.Is(err, previewruntime.ErrIdentity) {
		t.Fatal("fixed role did not reject missing trusted identity before configuration", err)
	}
	if err := run([]string{previewruntime.RoutedIntegrityPrepareRoleV3, "--config", "untrusted"}); err == nil {
		t.Fatal("fixed preparation role accepted administrative arguments")
	}
}
