//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const RoutedMigrationSourceRoleV3 = "--andeiva-routed-migration-source-v3"
const RoutedMigrationStateRoleV3 = "--andeiva-routed-migration-state-v3"
const routedMigrationRequestLimitV3 = firewallipc.MaxFrame

type routedMigrationRequestV3 struct {
	Version    int                              `json:"version"`
	ParentPID  int                              `json:"parent_pid"`
	Metadata   Metadata                         `json:"metadata"`
	Identities Identities                       `json:"identities"`
	Expected   [2]configpoc.LegacyFingerprintV2 `json:"expected"`
	Firewall   configpoc.Revision               `json:"firewall"`
	Local      configpoc.Revision               `json:"local"`
}
type routedMigrationReplyV3 struct {
	Version   int                       `json:"version"`
	Request   string                    `json:"request"`
	Namespace uint64                    `json:"namespace"`
	HelperPID int32                     `json:"helper_pid,omitempty"`
	State     *firewalladmin.LeaseState `json:"state,omitempty"`
}

type routedMigrationVerifierV3 struct {
	gateway    *os.File // Borrowed until the complete cold-migration call returns.
	metadata   Metadata
	identities Identities
}

func (v *routedMigrationVerifierV3) VerifyMigratedSources(ctx context.Context, expected [2]configpoc.LegacyFingerprintV2, firewall, local configpoc.Revision) error {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || v == nil || v.gateway == nil || v.metadata.Validate() != nil || v.identities.Validate() != nil {
		return ErrIdentity
	}
	if verifyRoutedMigrationScopeV3(v.gateway, v.metadata, false) != nil {
		return ErrIdentity
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return ErrIdentity
	}
	request := routedMigrationRequestV3{Version: 1, ParentPID: os.Getpid(), Metadata: v.metadata, Identities: v.identities, Expected: expected, Firewall: firewall, Local: local}
	data, err := json.Marshal(request)
	if err != nil || len(data) > routedMigrationRequestLimitV3 {
		return ErrConfiguration
	}
	before, err := v.runChild(ctx, self, RoutedMigrationStateRoleV3, data)
	if err != nil {
		return err
	}
	if _, err = v.runChild(ctx, self, RoutedMigrationSourceRoleV3, data); err != nil {
		return err
	}
	after, err := v.runChild(ctx, self, RoutedMigrationStateRoleV3, data)
	if err != nil || before.HelperPID != after.HelperPID || before.State == nil || after.State == nil || *before.State != *after.State || verifyRoutedMigrationScopeV3(v.gateway, v.metadata, false) != nil {
		return ErrUnavailable
	}
	return nil
}

func (v *routedMigrationVerifierV3) runChild(ctx context.Context, self, role string, data []byte) (routedMigrationReplyV3, error) {
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args, err := routedMigrationSourceArgsV3(self, v.identities, role)
	if err != nil {
		return routedMigrationReplyV3{}, err
	}
	var cmd *exec.Cmd
	switch role {
	case RoutedMigrationSourceRoleV3:
		// #nosec G204 -- Fixed executable/role, validated numeric identities and root-owned self; namespace is inherited FD3, never a caller path or command.
		cmd = exec.CommandContext(call, "/usr/bin/nsenter", args...)
	case RoutedMigrationStateRoleV3:
		// #nosec G204 -- Fixed capless state-only role and validated numeric identities/root-owned binary, without administrative input or a shell.
		cmd = exec.CommandContext(call, "/usr/bin/setpriv", args...)
	default:
		return routedMigrationReplyV3{}, ErrIdentity
	}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.ExtraFiles = []*os.File{v.gateway}
	cmd.Stdin = bytes.NewReader(data)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output, diagnostic routedMigrationOutputV3
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	// Pdeathsig belongs to the creating Linux thread, not merely the process.
	if runPinnedMigrationCommandV3(cmd.Start, cmd.Wait) != nil || call.Err() != nil {
		return routedMigrationReplyV3{}, ErrUnavailable
	}
	digest := sha256.Sum256(data)
	var reply routedMigrationReplyV3
	if firewallipc.Decode(output.Bytes(), &reply) != nil || reply.Version != 1 || reply.Request != hex.EncodeToString(digest[:]) || reply.Namespace != v.metadata.GatewayNamespace {
		return routedMigrationReplyV3{}, ErrUnavailable
	}
	if role == RoutedMigrationStateRoleV3 {
		if reply.HelperPID <= 1 || reply.State == nil || reply.State.Phase != "idle" {
			return routedMigrationReplyV3{}, ErrUnavailable
		}
	} else if reply.HelperPID != 0 || reply.State != nil {
		return routedMigrationReplyV3{}, ErrUnavailable
	}
	return reply, nil
}

type routedMigrationOutputV3 struct{ bytes.Buffer }

func (b *routedMigrationOutputV3) Write(data []byte) (int, error) {
	if len(data) > 4096-b.Len() {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(data)
}

func routedMigrationSourceArgsV3(self string, ids Identities, role string) ([]string, error) {
	if ids.Validate() != nil || self == "" || trustedRoutedExecutableV3(self) != nil {
		return nil, ErrIdentity
	}
	uid, gid, groups, caps := ids.HelperUID, ids.IPCGID, strconv.FormatUint(uint64(ids.IPCGID), 10), "-all,+net_admin"
	if role == RoutedMigrationStateRoleV3 {
		uid, gid, caps = ids.APIUID, ids.APIGID, "-all"
	} else if role != RoutedMigrationSourceRoleV3 {
		return nil, ErrIdentity
	}
	args := []string{"--reuid=" + strconv.FormatUint(uint64(uid), 10), "--regid=" + strconv.FormatUint(uint64(gid), 10), "--groups=" + groups, "--bounding-set=" + caps, "--inh-caps=" + caps, "--ambient-caps=" + caps, "--no-new-privs", "--", self, role}
	if role == RoutedMigrationSourceRoleV3 {
		args = append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/setpriv"}, args...)
	}
	return args, nil
}

func verifyRoutedMigrationScopeV3(gateway *os.File, m Metadata, inside bool) error {
	if gateway == nil || m.Validate() != nil {
		return ErrIdentity
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	flags, err := unix.FcntlInt(gateway.Fd(), unix.F_GETFL, 0)
	kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, gateway.Fd(), unix.NS_GET_NSTYPE, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(int(gateway.Fd()), &st) != nil || unix.Fstatfs(int(gateway.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC || errno != 0 || kind != unix.CLONE_NEWNET || st.Ino != m.GatewayNamespace {
		return ErrIdentity
	}
	want := m.HostNamespace
	if inside {
		want = m.GatewayNamespace
	}
	actual, err := namespaceID("/proc/self/ns/net")
	thread, threadErr := namespaceID("/proc/thread-self/ns/net")
	if err != nil || threadErr != nil || actual != want || thread != want {
		return ErrIdentity
	}
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot, e := canonicalBoot(raw)
	if err != nil || e != nil || boot != m.BootID {
		return ErrIdentity
	}
	return nil
}

// RunRoutedMigrationSourceRoleV3 is a fixed, read-only installer child. Its
// namespace descriptor and bounded request originate only from a root parent.
// It owns no store descriptor and has no apply or administrative dispatch path.
func RunRoutedMigrationSourceRoleV3(ctx context.Context) error {
	return runRoutedMigrationRoleV3(ctx, true)
}
func RunRoutedMigrationStateRoleV3(ctx context.Context) error {
	return runRoutedMigrationRoleV3(ctx, false)
}
func runRoutedMigrationRoleV3(ctx context.Context, helper bool) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	var pipe unix.Stat_t
	flags, err := unix.FcntlInt(0, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(0, &pipe) != nil || pipe.Mode&unix.S_IFMT != unix.S_IFIFO || pipe.Uid != 0 || unix.SetNonblock(0, true) != nil {
		return ErrIdentity
	}
	var output unix.Stat_t
	outputFlags, outputErr := unix.FcntlInt(1, unix.F_GETFL, 0)
	if outputErr != nil || outputFlags&unix.O_ACCMODE != unix.O_WRONLY || unix.Fstat(1, &output) != nil || output.Mode&unix.S_IFMT != unix.S_IFIFO || output.Uid != 0 || (output.Dev == pipe.Dev && output.Ino == pipe.Ino) {
		return ErrIdentity
	}
	input := os.NewFile(0, "migration-source-request")
	if input == nil {
		return ErrIdentity
	}
	defer input.Close()
	if input.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(input, routedMigrationRequestLimitV3+1))
	var request routedMigrationRequestV3
	if err != nil || len(data) == 0 || len(data) > routedMigrationRequestLimitV3 || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &request) != nil || request.Version != 1 || request.ParentPID <= 1 || request.ParentPID != os.Getppid() || request.Identities.Validate() != nil || checkPrivileges(request.Identities, helper) != nil {
		return ErrIdentity
	}
	parent, err := os.Open(fmt.Sprintf("/proc/%d/status", request.ParentPID))
	if err != nil {
		return ErrIdentity
	}
	status, readErr := io.ReadAll(io.LimitReader(parent, 65537))
	closeErr := parent.Close()
	if readErr != nil || closeErr != nil || !rootRoutedParentStatusV3(status, request.ParentPID) || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || os.Getppid() != request.ParentPID {
		return ErrIdentity
	}
	gateway := os.NewFile(3, "migration-source-namespace")
	if gateway == nil {
		return ErrIdentity
	}
	defer gateway.Close()
	unix.CloseOnExec(3)
	if verifyRoutedMigrationScopeV3(gateway, request.Metadata, helper) != nil {
		return ErrIdentity
	}
	var result routedMigrationReplyV3
	if helper {
		kernel, e := newRoutedKernelV3(request.Metadata)
		if e != nil {
			return e
		}
		if e = verifyRoutedMigrationSourceV3(ctx, kernel, request.Expected, request.Firewall, request.Local); e != nil {
			return e
		}
	} else {
		state, pid, e := observeMigrationGuardianV3(ctx, request.Metadata, request.Identities, request.Firewall.Hash)
		if e != nil {
			return e
		}
		result.State = &state
		result.HelperPID = pid
	}
	if verifyRoutedMigrationScopeV3(gateway, request.Metadata, helper) != nil || os.Getppid() != request.ParentPID {
		return ErrIdentity
	}

	digest := sha256.Sum256(data)
	result.Version = 1
	result.Request = hex.EncodeToString(digest[:])
	result.Namespace = request.Metadata.GatewayNamespace
	return json.NewEncoder(os.Stdout).Encode(result)
}

// Start and Wait must stay on the same live Linux thread: Pdeathsig is tied to
// that thread. A future worker may retire its thread only after Wait returns.
func runPinnedMigrationCommandV3(start, wait func() error) error {
	if start == nil || wait == nil {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := start(); err != nil {
		return err
	}
	return wait()
}
