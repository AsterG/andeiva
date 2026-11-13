//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"golang.org/x/sys/unix"
)

// This opt-in fixture requires a root laboratory harness and three fresh
// namespaces. It does not qualify helper identities, transactions or traffic.
func TestNativeRoutedKernelV3(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_KERNEL_V3") != "1" {
		t.Skip("requires the isolated Debian laboratory harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("native kernel fixture is restricted to an authorized root laboratory")
	}
	inherited := func(fd int) uint64 {
		t.Helper()
		if fd < 3 || fd > 5 {
			t.Fatal("unexpected inherited namespace descriptor")
		}
		path := fmt.Sprintf("/proc/self/fd/%d", fd)
		var filesystem unix.Statfs_t
		var stat unix.Stat_t
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || kind != unix.CLONE_NEWNET || unix.Fstatfs(fd, &filesystem) != nil || filesystem.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &stat) != nil || stat.Ino == 0 {
			t.Fatalf("inherited descriptor %d is not a network namespace", fd)
		}
		actual, statErr := namespaceID(path)
		if statErr != nil || actual != stat.Ino {
			t.Fatal("inherited namespace identity is inconsistent")
		}
		unix.CloseOnExec(fd)
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if flagErr != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("namespace anchor would be inherited by a subprocess")
		}
		return stat.Ino
	}
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fixture gateway must contain only loopback")
	}
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := canonicalBoot(bootBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := Metadata{SchemaVersion: 1, RunID: strings.Repeat("c", 32), BootID: boot, HostNamespace: inherited(3), GatewayNamespace: current, SourceNamespace: inherited(4), SinkNamespace: inherited(5)}
	kernel, err := newRoutedKernelV3(m)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, table := range []routedactivation.Table{routedactivation.LegacyTable, routedactivation.RoutedTable, routedactivation.LocalTable} {
		if _, present, err := kernel.Observe(ctx, table); err != nil || present {
			t.Fatal("fresh gateway contains an existing managed table", table, err)
		}
	}
	enabled := true
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "native-kernel", Enabled: &enabled, Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}}
	artifact, err := firewallnft.Compile(config)
	if err != nil || kernel.Check(ctx, artifact.Create) != nil || kernel.Apply(ctx, artifact.Create) != nil {
		t.Fatal("native check/apply failed", err)
	}
	verify := func(want configpoc.Revision) {
		t.Helper()
		data, present, err := kernel.Observe(ctx, routedactivation.LegacyTable)
		observed, inspectErr := firewallnft.VerifyObservation(data, want)
		if err != nil || !present || inspectErr != nil || observed.Revision.Hash != want.Hash {
			t.Fatal("native effective rules differ", err, inspectErr)
		}
	}
	verify(artifact.Revision)
	if kernel.Check(ctx, []byte("{")) == nil {
		t.Fatal("malformed batch passed native validation")
	}
	verify(artifact.Revision)
	config.Rules[0].Action = "deny"
	replacement, err := firewallnft.Compile(config)
	if err != nil || kernel.Check(ctx, replacement.Batch) != nil || kernel.Apply(ctx, replacement.Batch) != nil {
		t.Fatal("native replacement failed", err)
	}
	verify(replacement.Revision)
	// A valid check-only batch would succeed in the parent namespace. The
	// adapter must reject it because this launching thread left the gateway.
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
			// Returning while still locked terminates a tainted OS thread.
		}()
		gateway, openErr := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			result <- openErr
			return
		}
		defer unix.Close(gateway)
		if err := unix.Setns(3, unix.CLONE_NEWNET); err != nil {
			result <- err
			return
		}
		restored = false
		check, commandErr := routedKernelCommandV3(ctx, "check", 0)
		var output, diagnostic helperOutput
		if commandErr == nil {
			check.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
			check.Stdin = strings.NewReader(string(artifact.Create))
			check.Stdout, check.Stderr = &output, &diagnostic
			commandErr = check.Run()
		}
		denied := kernel.Check(ctx, artifact.Create)
		restoreErr := unix.Setns(gateway, unix.CLONE_NEWNET)
		restored = restoreErr == nil
		if commandErr != nil || !errors.Is(denied, ErrUnavailable) || !restored {
			result <- errors.New("launching-thread rejection or restoration failed")
			return
		}
		result <- nil
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("launching-thread fixture timed out")
	}
	verify(replacement.Revision)
	t.Log("native check/apply/readback and divergent-thread rejection passed; no traffic or helper-process qualification")
}
