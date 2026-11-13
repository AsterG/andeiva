//go:build linux && !andeiva_native_dhcp_diagnostics

package previewruntime

import (
	"context"
	"testing"
)

func nativeDHCPJobsCollectV4(*testing.T, context.Context, Metadata) func() { return func() {} }
