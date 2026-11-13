//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"syscall"
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
	if m.ValidateRouted() != nil {
		return nil, ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	k := &routedKernelV3{namespace: m.GatewayNamespace, host: m.HostNamespace}
	if !k.bound() {
		return nil, ErrIdentity
	}
	return k, nil
}

func routedKernelCommandV3(ctx context.Context, operation string, table routedactivation.Table) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	var cmd *exec.Cmd
	switch operation {
	case "check":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "--check", "-j", "-f", "-")
	case "apply":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
	case "tables":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "tables")
	case "observe":
		switch table {
		case routedactivation.LegacyTable:
			cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", firewallnft.TableName)
		case routedactivation.RoutedTable:
			cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", routednft.TableName)
		case routedactivation.LocalTable:
			cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", localnft.TableName)
		}
	}
	if cmd == nil {
		return nil, ErrIdentity
	}
	// The caller pins its launching OS thread through Wait. A helper death
	// must also terminate nft after its in-process timeout has disappeared.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func (k *routedKernelV3) bound() bool {
	if k == nil || k.namespace == 0 || k.host == 0 || k.namespace == k.host {
		return false
	}
	leader, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		return false
	}
	thread, err := namespaceID("/proc/thread-self/ns/net")
	return err == nil && k.matchesNamespaces(leader, thread)
}

func (k *routedKernelV3) matchesNamespaces(leader, thread uint64) bool {
	return k != nil && k.namespace != 0 && k.host != 0 && k.namespace != k.host && leader == k.namespace && thread == k.namespace
}

func (k *routedKernelV3) execute(parent context.Context, operation string, table routedactivation.Table, input []byte) ([]byte, error) {
	if parent == nil || parent.Err() != nil || len(input) > routedactivation.MaxBatch || ((operation == "check" || operation == "apply") && len(input) == 0) || (operation != "check" && operation != "apply" && len(input) != 0) {
		return nil, ErrUnavailable
	}
	// exec inherits the launching thread's namespace, not necessarily the leader's.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !k.bound() {
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
