//go:build linux && !andeiva_native_dhcp_diagnostics

package previewruntime

import "testing"

type routedDHCPServerMountUnreadableErrorV1 struct{}

func (routedDHCPServerMountUnreadableErrorV1) Error() string { panic("must not render cause") }

func TestRoutedDHCPServerMountDiagnosticDefaultV1(t *testing.T) {
	for _, result := range []error{nil, ErrIdentity, ErrUnavailable} {
		if got := routedDHCPServerMountFailureV1("untrusted\nstage", routedDHCPServerMountUnreadableErrorV1{}, result); got != result {
			t.Fatal("normal build changed public error")
		}
	}
}
