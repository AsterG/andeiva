//go:build linux

package previewruntime

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedCgroupDrainV3RejectsRemainingDescendants(t *testing.T) {
	for _, raw := range []string{"", "41\n42\n", "42\n41\n", "41\n41\n", "42\n", "041\n", "41\ninvalid\n", "0\n"} {
		if routedCgroupOnlySupervisorV3([]byte(raw), 41) {
			t.Fatal("unproven descendant drainage accepted")
		}
	}
	if !routedCgroupOnlySupervisorV3([]byte("41\n"), 41) {
		t.Fatal("single supervisor rejected")
	}
}

func TestRoutedCgroupDrainV3Native(t *testing.T) {
	if os.Getenv("ANDEIVA_ROUTED_CGROUP_NATIVE") != "1" {
		t.Skip("explicit dedicated root service qualification only")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 || waitRoutedCgroupDrainedV3() != nil {
		t.Fatal("exclusive root service cgroup required")
	}
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	slot, err := openRoutedRetirementSlotV3(area)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	// The helper leader exits and is waited, while its child remains in the
	// same real service cgroup. No user command or network operation is involved.
	cmd := exec.Command("/bin/sh", "-c", "/bin/sleep 30 >/dev/null 2>&1 & printf '%s' \"$!\"")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil || pid <= 1 {
		t.Fatal("grandchild PID")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	// Pinning a recycled PID is not authority to signal it. The live target
	// must still belong to this exact dedicated cgroup before cleanup is armed.
	group, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	members, memberErr := os.ReadFile("/sys/fs/cgroup" + routedSupervisorCgroupV3 + "/cgroup.procs")
	fields := strings.Fields(string(members))
	self := strconv.Itoa(os.Getpid())
	child := strconv.Itoa(pid)
	live := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	ready, pollErr := unix.Poll(live, 0)
	if err != nil || memberErr != nil || string(group) != "0::"+routedSupervisorCgroupV3+"\n" || len(fields) != 2 || !((fields[0] == self && fields[1] == child) || (fields[1] == self && fields[0] == child)) || pollErr != nil || ready != 0 {
		t.Fatal("grandchild identity no longer belongs exclusively to test cgroup")
	}
	defer unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
	m := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 40, GatewayNamespace: 42}
	ids := Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}
	closed := false
	cleanup := func() error { closed = true; return nil }
	if err := finishRoutedScopeRetirementV3(slot, m, ids, cleanup); !errors.Is(err, ErrUnavailable) || closed {
		t.Fatal("retained descendant did not fence namespace cleanup", err)
	}
	before, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil || !bytes.Equal(before, make([]byte, RootRetirementReceiptSizeV3)) {
		t.Fatal("receipt issued before drainage", err)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := finishRoutedScopeRetirementV3(slot, m, ids, cleanup); err != nil || !closed {
		t.Fatal("drained service did not finalize", err)
	}
	after, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRootRetirementReceiptV3(after); err != nil {
		t.Fatal("invalid drained receipt", err)
	}
	t.Log("real orphan grandchild after leader Wait blocks cleanup and receipt; pidfd exit permits finalization. Namespace cleanup callback is a test witness, not network activation")
}
