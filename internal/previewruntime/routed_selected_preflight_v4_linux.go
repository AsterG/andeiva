//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

type RoutedSelectedPreflightOptionsV4 struct {
	Metadata                          Metadata
	Identities                        Identities
	Store, Admission, Plan, Emergency RoutedReaderRootV3
	Budget                            configpoc.SelectionReadBudgetV2
	Identity                          networkexecutor.OwnedNamespaceIdentity
	Purpose                           RoutedSelectedPreflightPurposeV4
	Work                              configpoc.RoutedWorkReferenceV1
}

type routedSelectedPreflightBootstrapV4 struct {
	Version  int                                    `json:"version"`
	Nonce    string                                 `json:"nonce"`
	Parent   int                                    `json:"parent"`
	Start    uint64                                 `json:"start,string"`
	Metadata Metadata                               `json:"metadata"`
	IDs      Identities                             `json:"identities"`
	Access   [4]recoveryreserve.ReaderAccessV2      `json:"access"`
	Profiles [3]recoveryreserve.ProfileV2           `json:"profiles"`
	Budget   configpoc.SelectionReadBudgetV2        `json:"budget"`
	Identity networkexecutor.OwnedNamespaceIdentity `json:"identity"`
	Purpose  RoutedSelectedPreflightPurposeV4       `json:"purpose"`
	Work     configpoc.RoutedWorkReferenceV1        `json:"work"`
}

func (b routedSelectedPreflightBootstrapV4) valid() bool {
	nonce, err := hex.DecodeString(b.Nonce)
	if b.Version != 4 || err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != b.Nonce || b.Parent <= 1 || b.Start == 0 || b.Metadata.ValidateRouted() != nil || b.IDs.Validate() != nil {
		return false
	}
	i := b.Identity
	if i.UID != b.IDs.HelperUID || i.GID != b.IDs.IPCGID || i.Namespace == 0 || i.Host == 0 || i.Namespace == i.Host || !bootPattern.MatchString(i.BootID) || !ValidRun(i.RunID) {
		return false
	}
	for _, access := range b.Access {
		if access.Version != 1 || access.OwnerUID != b.IDs.APIUID || access.ReaderGID == 0 || access.ReaderGID != b.Access[0].ReaderGID || access.ReaderGID == b.IDs.APIGID || access.ReaderGID == b.IDs.IPCGID {
			return false
		}
	}
	if b.Purpose == RoutedPreflightRetirementV4 {
		return b.Work == (configpoc.RoutedWorkReferenceV1{})
	}
	return b.Purpose == RoutedPreflightDHCPV4 && i.Namespace == b.Metadata.GatewayNamespace && i.Host == b.Metadata.HostNamespace && i.BootID == b.Metadata.BootID && i.RunID == b.Metadata.RunID && routedPrivateHashV4(b.Work.Work) && b.Work.Lineage != "" && len(b.Work.Lineage) <= 128 && b.Work.Generation != 0
}

func routedPreflightProcessV4(uid, euid, gid, egid int, groups []int, status string, b routedSelectedPreflightBootstrapV4) error {
	if !b.valid() || len(status) > 65536 || !matchesIdentity(uid, b.IDs.HelperUID) || !matchesIdentity(euid, b.IDs.HelperUID) || !matchesIdentity(gid, b.IDs.IPCGID) || !matchesIdentity(egid, b.IDs.IPCGID) || privilegeFields(status, false) != nil {
		return ErrIdentity
	}
	hasReader := false
	for _, group := range groups {
		if matchesIdentity(group, b.Access[0].ReaderGID) {
			hasReader = true
		} else if !matchesIdentity(group, b.IDs.IPCGID) {
			return ErrIdentity
		}
	}
	if !hasReader {
		return ErrIdentity
	}
	return nil
}

// ReadRoutedSelectedPreflightV4 neither opens a writer nor owns its publication
// barrier. Root must retain that barrier until all consumers finish. No path,
// executable or identity is accepted from an API request.
func ReadRoutedSelectedPreflightV4(ctx context.Context, o RoutedSelectedPreflightOptionsV4) (out RoutedSelectedPreflightResultV4, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return out, ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, configpoc.IntegrityInspectionDeadlineV1)
	defer cancel()
	start, _, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil {
		return out, ErrIdentity
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return out, ErrUnavailable
	}
	b := routedSelectedPreflightBootstrapV4{Version: 4, Nonce: hex.EncodeToString(nonce[:]), Parent: os.Getpid(), Start: start, Metadata: o.Metadata, IDs: o.Identities, Budget: o.Budget, Identity: o.Identity, Purpose: o.Purpose, Work: o.Work}
	var files []*os.File
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	var seen []os.FileInfo
	for i, resource := range []RoutedReaderRootV3{o.Store, o.Admission, o.Plan, o.Emergency} {
		if resource.Root == nil || resource.Access.CheckDirectory(resource.Root) != nil {
			return out, ErrIdentity
		}
		file, e := resource.Root.Open(".")
		if e != nil {
			return out, ErrIdentity
		}
		files = append(files, file)
		info, e := file.Stat()
		if e != nil {
			return out, ErrIdentity
		}
		for _, previous := range seen {
			if os.SameFile(previous, info) {
				return out, ErrIdentity
			}
		}
		seen = append(seen, info)
		b.Access[i] = resource.Access
		if i > 0 {
			b.Profiles[i-1] = resource.Profile
		}
	}
	if !b.valid() {
		return out, ErrIdentity
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return out, ErrIdentity
	}
	bootR, bootW, err := os.Pipe()
	if err != nil {
		return out, ErrUnavailable
	}
	files = append(files, bootR, bootW)
	replyR, replyW, err := os.Pipe()
	if err != nil {
		return out, ErrUnavailable
	}
	files = append(files, replyR, replyW)
	args := []string{"--reuid=" + strconv.FormatUint(uint64(b.IDs.HelperUID), 10), "--regid=" + strconv.FormatUint(uint64(b.IDs.IPCGID), 10), "--groups=" + strconv.FormatUint(uint64(b.Access[0].ReaderGID), 10), "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, RoutedSelectedPreflightRoleV4}
	// #nosec G204 -- Fixed setpriv/role, trusted current executable and validated numeric bootstrap identities; no shell or caller path.
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", args...)
	cmd.ExtraFiles = append(append([]*os.File{}, files[:4]...), bootR, replyW)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if cmd.Start() != nil {
		return out, ErrUnavailable
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	childStart, childParent, err := routedDHCPOwnerProcessV3(cmd.Process.Pid)
	if err != nil || childParent != os.Getpid() {
		return out, ErrIdentity
	}
	_ = bootR.Close()
	_ = replyW.Close()
	deadline, _ := ctx.Deadline()
	if bootW.SetWriteDeadline(deadline) != nil || replyR.SetReadDeadline(deadline) != nil || routedPrivateWriteV4(bootW, b) != nil {
		return out, ErrUnavailable
	}
	_ = bootW.Close()
	raw, err := io.ReadAll(io.LimitReader(replyR, routedPrivateFrameV4+1))
	var reply routedSelectedPreflightReplyV4
	if err != nil || routedPrivateDecodeV4(raw, &reply) != nil || reply.Version != 4 || reply.Nonce != b.Nonce || reply.PID != cmd.Process.Pid || reply.Start != childStart || routedPreflightResultV4(reply.Result, b.Purpose, b.Identity, b.Work) != nil {
		return out, ErrIdentity
	}
	// Wait proves complete EOF and successful role completion, not just a prefix.
	err = cmd.Wait()
	waited = true
	if err != nil || ctx.Err() != nil {
		return out, ErrUnavailable
	}
	return reply.Result, nil
}

// The role adopts FD3..6 readonly roots, FD7 bootstrap and FD8 result. It runs
// capless as helper UID + reader group, without namespace entry or effects.
func RunRoutedSelectedPreflightRoleV4(ctx context.Context) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, configpoc.IntegrityInspectionDeadlineV1)
	defer cancel()
	var files [6]*os.File
	var roots [4]*os.Root
	defer func() {
		for _, r := range roots {
			if r != nil {
				result = errors.Join(result, r.Close())
			}
		}
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	seen := map[[2]uint64]bool{}
	for i := range files {
		fd := i + 3
		var st unix.Stat_t
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || unix.Fstat(fd, &st) != nil {
			return ErrIdentity
		}
		key := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[key] {
			return ErrIdentity
		}
		seen[key] = true
		want := unix.O_RDONLY
		if i == 5 {
			want = unix.O_WRONLY
		}
		if flags&unix.O_ACCMODE != want || i < 4 && st.Mode&unix.S_IFMT != unix.S_IFDIR || i >= 4 && (st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Uid != 0) {
			return ErrIdentity
		}
		if i >= 4 && unix.SetNonblock(fd, true) != nil {
			return ErrIdentity
		}
		files[i] = os.NewFile(uintptr(fd), "routed-preflight")
		unix.CloseOnExec(fd)
	}
	deadline, _ := ctx.Deadline()
	if files[4].SetReadDeadline(deadline) != nil || files[5].SetWriteDeadline(deadline) != nil {
		return ErrIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(files[4], 16385))
	var b routedSelectedPreflightBootstrapV4
	if err != nil || len(raw) > 16384 || routedPrivateDecodeV4(raw, &b) != nil || !b.valid() || os.Getppid() != b.Parent {
		return ErrIdentity
	}
	groups, err := os.Getgroups()
	status, se := routedDHCPOwnerReadV3("/proc/self/status", 65536)
	parentStatus, pe := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(b.Parent)+"/status", 65536)
	start, _, ste := routedDHCPOwnerProcessV3(b.Parent)
	if err != nil || se != nil || pe != nil || ste != nil || start != b.Start || !rootRoutedParentStatusV3(parentStatus, b.Parent) || routedPreflightProcessV4(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, string(status), b) != nil || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || os.Getppid() != b.Parent {
		return ErrIdentity
	}
	for i := range roots {
		roots[i], err = os.OpenRoot("/proc/self/fd/" + strconv.Itoa(i+3))
		if err != nil || b.Access[i].CheckDirectory(roots[i]) != nil {
			return ErrIdentity
		}
		before, be := files[i].Stat()
		after, ae := roots[i].Stat(".")
		if be != nil || ae != nil || !os.SameFile(before, after) {
			return ErrIdentity
		}
	}
	var pools [3]*recoveryreserve.ReadOnlyPoolV2
	defer func() {
		for _, p := range pools {
			if p != nil {
				result = errors.Join(result, p.Close())
			}
		}
	}()
	for i := range pools {
		pools[i], err = recoveryreserve.OpenReadOnlyV2(roots[i+1], b.Access[i+1], b.Profiles[i])
		if err != nil {
			return err
		}
	}
	reader, err := configpoc.NewRoutedSelectionReaderV2(roots[0], configpoc.SelectionReaderOptionsV2{Access: b.Access[0], Identity: b.Identity, Admission: pools[0], Plan: pools[1], Emergency: pools[2], Budget: b.Budget})
	if err != nil {
		return err
	}
	out, err := routedReadPreflightV4(ctx, reader, b.Purpose, b.Identity, b.Work)
	if err != nil {
		return err
	}
	selfStart, _, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil || os.Getppid() != b.Parent || ctx.Err() != nil {
		return ErrIdentity
	}
	return routedPrivateWriteV4(files[5], routedSelectedPreflightReplyV4{Version: 4, Nonce: b.Nonce, PID: os.Getpid(), Start: selfStart, Result: out})
}

func routedReadPreflightV4(ctx context.Context, reader *configpoc.RoutedSelectionReaderV2, purpose RoutedSelectedPreflightPurposeV4, identity networkexecutor.OwnedNamespaceIdentity, work configpoc.RoutedWorkReferenceV1) (out RoutedSelectedPreflightResultV4, err error) {
	out.Identity = identity
	if purpose == RoutedPreflightRetirementV4 {
		source, e := reader.ObserveRetirementSourceV3(ctx, identity, func(configpoc.RoutedRetirementSourceV3) error { return nil })
		if e != nil || !source.Valid() {
			return out, ErrIdentity
		}
		out.Reference = source.Reference()
	} else if purpose == RoutedPreflightDHCPV4 {
		before, e := reader.Observe(ctx)
		if e != nil {
			return out, e
		}
		plan, e := reader.Resolve(ctx, before, configpoc.SelectionMatchTargetV2)
		if e != nil || !plan.Valid() || plan.Scope().Identity != identity || plan.Reference() != work {
			return out, ErrIdentity
		}
		out.Reference = before
		out.Work = work
		out.Resolution = plan.Resolution()
		_, out.Bundle = plan.Bundles()
		after, e := reader.Observe(ctx)
		if e != nil || before != after {
			return RoutedSelectedPreflightResultV4{}, ErrIdentity
		}
	} else {
		return out, ErrIdentity
	}
	if routedPreflightResultV4(out, purpose, identity, work) != nil {
		return RoutedSelectedPreflightResultV4{}, ErrIdentity
	}
	return out, nil
}
