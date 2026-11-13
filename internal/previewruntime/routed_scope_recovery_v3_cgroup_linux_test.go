//go:build linux

package previewruntime

import (
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedScopeRecoveryV3UnitRequiresExactMainAndNoDelegation(t *testing.T) {
	raw := "MainPID=200\nControlGroup=" + routedSupervisorCgroupV3 + "\nDelegate=no\nInvocationID=" + strings.Repeat("a", 32) + "\n"
	if _, err := parseScopeRecoveryUnitV3([]byte(raw), 200); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(raw, "MainPID=200", "MainPID=201", 1), strings.Replace(raw, "Delegate=no", "Delegate=yes", 1), strings.Replace(raw, routedSupervisorCgroupV3, "/system.slice/foreign.service", 1), strings.Replace(raw, strings.Repeat("a", 32), "", 1), raw + "Delegate=no\n", raw + "Unknown=1\n"} {
		if _, err := parseScopeRecoveryUnitV3([]byte(bad), 200); err == nil {
			t.Fatal("ambiguous/delegated unit accepted")
		}
	}
}
func TestRoutedScopeRecoveryV3OldEventsAreObservationOnly(t *testing.T) {
	old, current := RoutedScopeRecoveryFileV3{2, 10}, RoutedScopeRecoveryFileV3{2, 11}
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	deactivated, populated, err := scopeRecoveryOldEventsObservationV3(nil, unix.ENODEV, old, current, a, b)
	if err != nil || !deactivated || populated {
		t.Fatal("exact core deactivation observation refused", err)
	}
	for _, tc := range []struct {
		raw          string
		err          error
		old, current RoutedScopeRecoveryFileV3
		a, b         string
	}{
		{"", unix.ENOENT, old, current, a, b}, {"", unix.EACCES, old, current, a, b}, {"", unix.EIO, old, current, a, b},
		{"populated 0\nfrozen 0\n", unix.ENODEV, old, current, a, b}, {"", unix.ENODEV, old, old, a, b}, {"", unix.ENODEV, old, current, a, a},
		{"", unix.ENODEV, old, RoutedScopeRecoveryFileV3{3, 11}, a, b}, {"", unix.ENODEV, RoutedScopeRecoveryFileV3{}, current, a, b},
		{"", nil, old, current, a, b}, {"populated 0\nfrozen 1\n", nil, old, current, a, b}, {"populated 0\npopulated 0\n", nil, old, current, a, b},
	} {
		if _, _, err := scopeRecoveryOldEventsObservationV3([]byte(tc.raw), tc.err, tc.old, tc.current, tc.a, tc.b); !errors.Is(err, ErrIdentity) {
			t.Fatal("uncertain observation accepted", tc, err)
		}
	}
	for _, readErr := range []error{nil, io.EOF} {
		for _, value := range []string{"0", "1"} {
			d, p, err := scopeRecoveryOldEventsObservationV3([]byte("populated "+value+"\nfrozen 0\n"), readErr, old, current, a, b)
			if err != nil || d || p != (value == "1") {
				t.Fatal("live observation changed", err)
			}
		}
	}
}
