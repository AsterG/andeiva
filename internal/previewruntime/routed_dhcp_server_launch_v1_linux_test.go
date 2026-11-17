//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

func serverBootstrapFixtureV1() routedDHCPServerBootstrapV1 {
	return routedDHCPServerBootstrapV1{Version: 1, ParentPID: 2, ParentStartTicks: 10, HostMountNamespace: 30, DeadlineBootNS: int64(time.Hour), Metadata: Metadata{SchemaVersion: 2, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 10, GatewayNamespace: 20}, Config: dhcpserver.Config{SchemaVersion: 1, Enabled: true}, Bindings: []routedDHCPServerBindingWireV1{{InterfaceID: "lan", Role: "lan", Address: "198.18.1.1/24", Name: "lan0", SubnetID: 17}}, ServiceCgroups: []routedDHCPServerCgroupWireV1{{Role: "lan", Name: "dhcp-server-" + strings.Repeat("b", 32), Device: 1, Inode: 2}}, LeaseBudgetBytes: 4 << 20}
}

func TestRoutedDHCPServerLaunchBootstrapV1(t *testing.T) {
	b := serverBootstrapFixtureV1()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRoutedDHCPServerBootstrapV1(raw); err != nil || !reflect.DeepEqual(got, b) {
		t.Fatal("valid bootstrap rejected", err)
	}
	for _, bad := range [][]byte{nil, append(raw, raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"parent_pid":2`), []byte(`"parent_pid":1`), 1), bytes.Replace(raw, []byte(`"host_mount_namespace":30`), []byte(`"host_mount_namespace":0`), 1), append([]byte(`{"unexpected":true,`), raw[1:]...), bytes.Repeat([]byte("x"), routedDHCPServerBootstrapLimitV1+1)} {
		if _, err := decodeRoutedDHCPServerBootstrapV1(bad); err == nil {
			t.Fatal("ambiguous bootstrap accepted")
		}
	}
}

func TestRoutedDHCPServerSealedBootstrapV1(t *testing.T) {
	b := serverBootstrapFixtureV1()
	file, err := routedDHCPServerSealedBootstrapV1(b)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		t.Fatal("bootstrap not immutable", err, seals)
	}
	if _, err := file.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("sealed bootstrap modified")
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0400 {
		t.Fatal("bootstrap permissions")
	}
	raw := make([]byte, st.Size)
	if _, err := file.ReadAt(raw, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRoutedDHCPServerBootstrapV1(raw); err != nil {
		t.Fatal(err)
	}
}

func TestRoutedDHCPServerRoleCommandV1(t *testing.T) {
	files := []*os.File{os.Stdin, os.Stdin, os.Stdin}
	cmd := routedDHCPServerRoleCommandV1("/opt/andeiva/bin/runtime", files, 23)
	if !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/opt/andeiva/bin/runtime", RoutedDHCPServerRoleV1}) || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}) || cmd.SysProcAttr.Cloneflags != unix.CLONE_NEWNS || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || !cmd.SysProcAttr.UseCgroupFD || cmd.SysProcAttr.CgroupFD != 23 || !reflect.DeepEqual(cmd.ExtraFiles, files) || cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
		t.Fatal("fixed launch boundary changed")
	}
	if _, err := StartRoutedDHCPServerV1(nil, RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if RunRoutedDHCPServerRoleV1(nil) != ErrIdentity {
		t.Fatal("role accepted without Root assembly")
	}
}

func TestRoutedDHCPServerLaunchChildV1(t *testing.T) {
	if os.Getenv("ANDEIVA_DHCP_SERVER_LIFETIME_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	file := os.NewFile(3, "test-lifetime")
	defer file.Close()
	var one [1]byte
	n, err := file.Read(one[:])
	if n != 0 || err != io.EOF {
		t.Fatal("lifetime channel accepted command", err)
	}
}

func TestRoutedDHCPServerLaunchStopUsesPinnedLeaderAndLifetimeEOFV1(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRoutedDHCPServerLaunchChildV1$", "-test.count=1")
	cmd.Env = []string{"ANDEIVA_DHCP_SERVER_LIFETIME_CHILD=1"}
	cmd.ExtraFiles = []*os.File{read}
	fd, done, err := routedDHCPServerStartV1(cmd)
	if err != nil {
		t.Fatal(err)
	}
	launch := &RoutedDHCPServerLaunchV1{pid: cmd.Process.Pid, pidfd: fd, control: write, done: done}
	if !launch.Alive() {
		t.Fatal("retained live pidfd unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := launch.Stop(ctx); err != nil {
		t.Fatal("lifetime stop failed", err)
	}
	if launch.Alive() || launch.Stop(ctx) != nil {
		t.Fatal("stop did not remain terminal/idempotent")
	}
}
