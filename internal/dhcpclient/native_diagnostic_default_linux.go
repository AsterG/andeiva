//go:build linux && !andeiva_native_dhcp_diagnostics

package dhcpclient

import "io"

// Ordinary artifacts retain the original discard behavior and create no files.
type clientDiagnostic struct{}

func openClientDiagnostic() (*clientDiagnostic, error) { return nil, nil }
func (*clientDiagnostic) stderr() io.Writer            { return io.Discard }
func (*clientDiagnostic) event(string, string, int)    {}
func (*clientDiagnostic) leaseEvent(Event)             {}
func (*clientDiagnostic) close()                       {}
