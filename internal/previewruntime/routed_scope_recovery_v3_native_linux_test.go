//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func scopeStoreNativeEnvironmentV3(uid, euid, ppid int, ci, release string) bool {
	return uid == 0 && euid == 0 && ppid == 1 && ci == "" && strings.Contains(release, "ID=debian\n") && strings.Contains(release, "VERSION_ID=\"13\"\n")
}
func scopeStoreNativeUnitV3(ctx context.Context) error {
	if trustedRoutedExecutableV3("/usr/bin/systemctl") != nil {
		return ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/systemctl", "--no-pager", "show", "--property=MainPID", "--property=ControlGroup", "--property=NotifyAccess", "--property=FileDescriptorStoreMax", "--property=FileDescriptorStorePreserve", "--property=PrivateMounts", "--property=KillMode", "--property=Transient", "--property=InvocationID", "andeiva-preview-grouped.service")
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	err := cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil {
		return errors.Join(err, call.Err(), ErrIdentity)
	}
	wanted := map[string]string{"MainPID": strconv.Itoa(os.Getpid()), "ControlGroup": routedSupervisorCgroupV3, "NotifyAccess": "main", "FileDescriptorStoreMax": "7", "FileDescriptorStorePreserve": "yes", "PrivateMounts": "yes", "KillMode": "control-group", "Transient": "yes"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return ErrIdentity
		}
		seen[key] = true
		if key == "InvocationID" {
			if !validHex(value, 16) {
				return ErrIdentity
			}
			continue
		}
		expected, ok := wanted[key]
		if !ok || value != expected {
			return ErrIdentity
		}
	}
	if len(seen) != len(wanted)+1 {
		return ErrIdentity
	}
	return nil
}

// Opt-in only: Root runs this test binary as the transient service's MainPID,
// after independently proving the fixed service/socket names are not installed.
// A failure after publication retains evidence; it never invents retirement.
func TestRoutedScopeRecoveryV3NativeStore(t *testing.T) {
	if os.Getenv("ANDEIVA_SCOPE_STORE_NATIVE") != "1" {
		t.Skip("explicit isolated Debian system-manager qualification only")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !scopeStoreNativeEnvironmentV3(os.Getuid(), os.Geteuid(), os.Getppid(), os.Getenv("CI"), string(release)) {
		t.Fatal("root MAIN, no CI and Debian 13 required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err = scopeStoreNativeUnitV3(ctx); err != nil {
		t.Fatal("fixed transient MAIN identity/properties", err)
	}
	mountID, err := namespaceID("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	hostMount, err := namespaceID("/proc/1/ns/mnt")
	if err != nil || hostMount == mountID {
		t.Fatal("private mount namespace required", err)
	}
	raw, err := readScopeRecoveryStoreV3(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(raw, nil) {
		t.Fatal("manager must start empty", err)
	}
	directory, err := os.MkdirTemp("/var/tmp", "andeiva-scope-store-")
	if err != nil {
		t.Fatal(err)
	}
	// No t.TempDir cleanup: uncertain stored anchors must retain their evidence.
	retained := false
	defer func() {
		if retained {
			t.Log("retained partial scope evidence", directory)
			return
		}
		if err := os.Remove(directory); err != nil {
			t.Error("remove empty owned fixture directory", err)
		}
	}()
	area, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	if err = area.Mkdir("namespace", 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !retained {
			if err := area.Remove("namespace"); err != nil {
				t.Error(err)
			}
		}
	}()
	namespaceArea, err := area.OpenRoot("namespace")
	if err != nil {
		t.Fatal(err)
	}
	defer namespaceArea.Close()
	slot, err := openScopeRecordSlotV3(area, true)
	if err != nil {
		t.Fatal("preallocated root manifest", err)
	}
	defer func() {
		if err := slot.Close(); err != nil {
			t.Error(err)
		}
		if !retained {
			if err := area.Remove(routedScopeRecordNameV3); err != nil {
				t.Error(err)
			}
		}
	}()
	gateway, err := CreateRoutedGatewayNamespaceV3(ctx, namespaceArea)
	if err != nil {
		t.Fatal("isolated gateway creation", err)
	}
	defer func() {
		if !retained {
			if err := gateway.Close(); err != nil {
				t.Error("owned namespace cleanup", err)
			}
		}
	}()
	hostID, err := namespaceID("/proc/self/ns/net")
	if err != nil || hostID == gateway.ID() {
		t.Fatal("nonhost gateway proof", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := canonicalBoot(boot)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: hex.EncodeToString(nonce[:]), BootID: bootID, HostNamespace: hostID, GatewayNamespace: gateway.ID()}
	ids := Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}
	underlay, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", gateway.underlay.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer underlay.Close()
	originalInfo, err := gateway.underlay.Stat()
	if err != nil {
		t.Fatal(err)
	}
	readInfo, err := underlay.Stat()
	if err != nil || !os.SameFile(originalInfo, readInfo) {
		t.Fatal("underlay identity", err)
	}
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mount.Close()
	cgroup, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	eventFD, err := unix.Openat(int(cgroup.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	events := os.NewFile(uintptr(eventFD), "native-owned-events")
	defer events.Close()
	anchors := RoutedScopeRecoveryAnchorsV3{slot.reader, gateway.File(), mount, underlay, gateway.directory, cgroup, events}
	record, err := PrepareRoutedScopeRecoveryRecordV3(ctx, metadata, ids, anchors)
	if err != nil {
		t.Fatal("capture seven real anchors", err)
	}
	if err = slot.publish(record); err != nil {
		t.Fatal("manifest fsync", err)
	}
	recovery, err := OpenRoutedScopeRecoveryV3(ctx, anchors)
	if err != nil {
		t.Fatal("readonly constructor", err)
	}
	defer func() {
		if err := recovery.Close(); err != nil {
			t.Error(err)
		}
	}()
	retained = true
	if err = recovery.Store(ctx); err != nil {
		t.Fatal("FDSTORE/barrier/manager readback", err)
	}
	if err = recovery.VerifyStored(ctx); err != nil {
		t.Fatal("independent exact store readback", err)
	}
	t.Log("seven real anchors stored and verified; no L2 or listener created")
	if err = recovery.DropStored(ctx); err != nil {
		t.Fatal("FDSTOREREMOVE/barrier/empty readback", err)
	}
	raw, err = readScopeRecoveryStoreV3(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(raw, nil) {
		t.Fatal("final manager store not empty", err)
	}
	if err = recovery.Close(); err != nil {
		t.Fatal("close local retained anchors", err)
	}
	retained = false
	if err = ctx.Err(); err != nil {
		t.Fatal(err)
	}
	t.Log("manager store empty and local anchors closed; no retirement receipt issued")
}

func TestRoutedScopeRecoveryV3NativeEnvironmentRefusesUnsafeRoles(t *testing.T) {
	release := "ID=debian\nVERSION_ID=\"13\"\n"
	if !scopeStoreNativeEnvironmentV3(0, 0, 1, "", release) {
		t.Fatal("intended profile refused")
	}
	for _, c := range []struct {
		uid, euid, ppid int
		ci, release     string
	}{{1000, 1000, 1, "", release}, {0, 1000, 1, "", release}, {0, 0, 100, "", release}, {0, 0, 1, "true", release}, {0, 0, 1, "", "ID=ubuntu\nVERSION_ID=\"24\"\n"}} {
		if scopeStoreNativeEnvironmentV3(c.uid, c.euid, c.ppid, c.ci, c.release) {
			t.Fatal("unsafe profile accepted")
		}
	}
}
