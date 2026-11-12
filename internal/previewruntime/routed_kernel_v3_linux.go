//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

// routedKernelV3 is constructed only inside an authenticated helper. It neither
// enters namespaces nor accepts executable paths, arguments or table names.
type routedKernelV3 struct{ namespace, host uint64 }

func newRoutedKernelV3(m Metadata) (*routedKernelV3, error) {
	if m.Validate() != nil {
		return nil, ErrIdentity
	}
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil || current != m.GatewayNamespace || current == m.HostNamespace {
		return nil, ErrIdentity
	}
	return &routedKernelV3{namespace: current, host: m.HostNamespace}, nil
}

func routedKernelCommandV3(ctx context.Context, operation string, table routedactivation.Table) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	switch operation {
	case "check":
		return exec.CommandContext(ctx, "/usr/sbin/nft", "--check", "-j", "-f", "-"), nil
	case "apply":
		return exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-"), nil
	case "tables":
		return exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "tables"), nil
	case "observe":
		switch table {
		case routedactivation.LegacyTable:
			return exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", firewallnft.TableName), nil
		case routedactivation.RoutedTable:
			return exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", routednft.TableName), nil
		case routedactivation.LocalTable:
			return exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", localnft.TableName), nil
		}
	}
	return nil, ErrIdentity
}

func (k *routedKernelV3) bound() bool {
	if k == nil || k.namespace == 0 || k.host == 0 || k.namespace == k.host {
		return false
	}
	actual, err := namespaceID("/proc/self/ns/net")
	return err == nil && actual == k.namespace
}

func (k *routedKernelV3) execute(parent context.Context, operation string, table routedactivation.Table, input []byte) ([]byte, error) {
	if parent == nil || parent.Err() != nil || !k.bound() || len(input) > routedactivation.MaxBatch || ((operation == "check" || operation == "apply") && len(input) == 0) || (operation != "check" && operation != "apply" && len(input) != 0) {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd, err := routedKernelCommandV3(ctx, operation, table)
	if err != nil {
		return nil, err
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	var output, diagnostic helperOutput
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	cmd.WaitDelay = 200 * time.Millisecond
	if cmd.Run() != nil || !k.bound() {
		return nil, ErrUnavailable
	}
	return output.Bytes(), nil
}

func (k *routedKernelV3) Check(ctx context.Context, input []byte) error {
	_, err := k.execute(ctx, "check", 0, input)
	return err
}
func (k *routedKernelV3) Apply(ctx context.Context, input []byte) error {
	_, err := k.execute(ctx, "apply", 0, input)
	return err
}
func (k *routedKernelV3) Observe(ctx context.Context, table routedactivation.Table) ([]byte, bool, error) {
	// Reject an unknown enum before any process, including the presence query.
	if _, err := routedKernelCommandV3(ctx, "observe", table); err != nil {
		return nil, false, err
	}
	listing, err := k.execute(ctx, "tables", 0, nil)
	if err != nil {
		return nil, false, err
	}
	present, err := routedactivation.TablePresence(listing, table)
	if err != nil || !present {
		return nil, false, err
	}
	data, err := k.execute(ctx, "observe", table, nil)
	return data, true, err
}

var _ routedactivation.Kernel = (*routedKernelV3)(nil)
