package nftfixture

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

var errLocalHandoff = errors.New("ANDEIVA_LOCAL_HANDOFF_INVALID")

// LocalAPIHandoff is supplied only by the root laboratory supervisor. No public
// request may choose these descriptors or identities. The caller retains their
// ownership and closes the child-side copies after launch.
type LocalAPIHandoff struct {
	UID, GID                           uint32
	RecoveryLAN, RecoveryLoopback      *os.File
	Transactions, Listeners, Bootstrap *os.File
}

type LocalHelperHandoff struct {
	UID, GID                                      uint32
	Transactions, Listeners, Collector, Bootstrap *os.File
}

type localDescriptorKind uint8

const (
	localLAN localDescriptorKind = iota
	localLoopback
	localStream
	localBootstrap
)

var apiDescriptorKinds = []localDescriptorKind{localLAN, localLoopback, localStream, localStream, localBootstrap}
var helperDescriptorKinds = []localDescriptorKind{localStream, localStream, localStream, localBootstrap}
var probeDescriptorKinds = []localDescriptorKind{localBootstrap}

func validLocalIdentity(uid, gid uint32) bool {
	return uid != 0 && gid != 0 && uid != ^uint32(0) && gid != ^uint32(0)
}

func localRunID(run string) bool {
	id, err := hex.DecodeString(run)
	return err == nil && len(id) == 16 && hex.EncodeToString(id) == run
}

func descriptorFlags(fd int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 {
		return 0, errLocalHandoff
	}
	return int(flags), nil
}

func socketAddress(fd int) (netip.AddrPort, bool) {
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return netip.AddrPort{}, false
	}
	switch a := address.(type) {
	case *syscall.SockaddrInet4:
		if a.Port < 1024 || a.Port > 65535 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), true
	case *syscall.SockaddrInet6:
		if a.ZoneId != 0 || a.Port < 1024 || a.Port > 65535 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)), true
	default:
		return netip.AddrPort{}, false
	}
}

func validRecoveryAddress(address netip.AddrPort, loopback bool) bool {
	a := address.Addr()
	return a.IsValid() && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && a.Zone() == "" && a.IsLoopback() == loopback && address.Port() >= 1024
}

func validLocalDescriptor(fd int, kind localDescriptorKind) bool {
	var st syscall.Stat_t
	if fd < 0 || syscall.Fstat(fd, &st) != nil {
		return false
	}
	flags, err := descriptorFlags(fd)
	if err != nil {
		return false
	}
	if kind == localBootstrap {
		return st.Mode&syscall.S_IFMT == syscall.S_IFIFO && flags&syscall.O_ACCMODE == syscall.O_RDONLY
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK || flags&syscall.O_ACCMODE != syscall.O_RDWR {
		return false
	}
	typeID, typeErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	listening, listenErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if typeErr != nil || listenErr != nil || typeID != syscall.SOCK_STREAM {
		return false
	}
	if kind == localStream {
		local, localErr := syscall.Getsockname(fd)
		peer, peerErr := syscall.Getpeername(fd)
		_, localUnix := local.(*syscall.SockaddrUnix)
		_, peerUnix := peer.(*syscall.SockaddrUnix)
		return listening == 0 && localErr == nil && peerErr == nil && localUnix && peerUnix
	}
	address, ok := socketAddress(fd)
	return listening == 1 && ok && validRecoveryAddress(address, kind == localLoopback)
}

func validateLocalFiles(files []*os.File, kinds []localDescriptorKind) error {
	if len(files) != len(kinds) {
		return errLocalHandoff
	}
	seen := make(map[[2]uint64]bool, len(files))
	for i, file := range files {
		if file == nil || !validLocalDescriptor(int(file.Fd()), kinds[i]) {
			return errLocalHandoff
		}
		var st syscall.Stat_t
		if syscall.Fstat(int(file.Fd()), &st) != nil {
			return errLocalHandoff
		}
		identity := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[identity] {
			return errLocalHandoff
		}
		seen[identity] = true
	}
	return nil
}

func (f *Fixture) localLaunchCommand(ctx context.Context, role, run, side string, uid, gid uint32, files []*os.File) (*exec.Cmd, error) {
	if !f.localOnly || !validLocalIdentity(f.uid, f.gid) || !validLocalIdentity(uid, gid) {
		return nil, errLocalHandoff
	}
	namespaceRole := "gateway"
	args := []string{}
	kinds := apiDescriptorKinds
	netAdmin := false
	switch role {
	case "api":
		if uid != f.uid || gid != f.gid || run != "" || side != "" {
			return nil, errLocalHandoff
		}
		args = []string{"--local-services", strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())}
	case "helper":
		if uid == f.uid || gid == f.gid || !localRunID(run) || side != "" {
			return nil, errLocalHandoff
		}
		args = []string{"--guardian", run, strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())}
		kinds, netAdmin = helperDescriptorKinds, true
	case "probe":
		if uid != f.uid || gid != f.gid || run != "" || (side != "source" && side != "sink") {
			return nil, errLocalHandoff
		}
		namespaceRole = side
		args = []string{"--local-probe", strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid()), side}
		kinds = probeDescriptorKinds
	default:
		return nil, errLocalHandoff
	}
	if err := validateLocalFiles(files, kinds); err != nil {
		return nil, err
	}
	cmd, err := f.commandWithIdentity(ctx, namespaceRole, f.self, args, "", true, netAdmin, uid, gid)
	if err != nil {
		return nil, err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, files...)
	return cmd, nil
}

func (f *Fixture) launchLocal(ctx context.Context, role, run, side string, uid, gid uint32, files []*os.File, stdout, stderr io.Writer) (*exec.Cmd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if os.Geteuid() != 0 {
		return nil, errLocalHandoff
	}
	cmd, err := f.localLaunchCommand(ctx, role, run, side, uid, gid, files)
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	f.children = append(f.children, child{cmd: cmd})
	return cmd, nil
}

// LaunchLocalAPI passes FD3 namespace, FD4 LAN recovery, FD5 loopback recovery,
// FD6 transactions, FD7 listeners and FD8 bootstrap. Its identity is the one
// fixed at fixture creation. No secrets appear in command arguments.
func (f *Fixture) LaunchLocalAPI(ctx context.Context, h LocalAPIHandoff, stdout, stderr io.Writer) (*exec.Cmd, error) {
	return f.launchLocal(ctx, "api", "", "", h.UID, h.GID, []*os.File{h.RecoveryLAN, h.RecoveryLoopback, h.Transactions, h.Listeners, h.Bootstrap}, stdout, stderr)
}

// LaunchLocalHelper passes FD3 namespace, FD4 transactions, FD5 listeners,
// FD6 collector and FD7 bootstrap. Both UID and GID differ from the API;
// NET_ADMIN is its only capability. It never inherits recovery listeners.
func (f *Fixture) LaunchLocalHelper(ctx context.Context, run string, h LocalHelperHandoff, stdout, stderr io.Writer) (*exec.Cmd, error) {
	return f.launchLocal(ctx, "helper", run, "", h.UID, h.GID, []*os.File{h.Transactions, h.Listeners, h.Collector, h.Bootstrap}, stdout, stderr)
}

// LaunchLocalProbe launches the fixed authenticated-probe role in source or
// sink, without capabilities. The runner must strictly decode its bounded
// bootstrap and permit only fixture destinations and protocol operations.
func (f *Fixture) LaunchLocalProbe(ctx context.Context, side string, bootstrap *os.File, stdout, stderr io.Writer) (*exec.Cmd, error) {
	return f.launchLocal(ctx, "probe", "", side, f.uid, f.gid, []*os.File{bootstrap}, stdout, stderr)
}

func validLocalProcessStatus(data []byte, uid, gid uint32, netAdmin bool) bool {
	wantCaps := uint64(0)
	if netAdmin {
		wantCaps = 1 << 12
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		key := parts[0]
		switch key {
		case "Uid:", "Gid:":
			if seen[key] || len(parts) != 5 {
				return false
			}
			want := uid
			if key == "Gid:" {
				want = gid
			}
			for _, value := range parts[1:] {
				if value != strconv.FormatUint(uint64(want), 10) {
					return false
				}
			}
		case "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:":
			if seen[key] || len(parts) != 2 {
				return false
			}
			value, err := strconv.ParseUint(parts[1], 16, 64)
			if err != nil || value != wantCaps {
				return false
			}
		case "NoNewPrivs:":
			if seen[key] || len(parts) != 2 || parts[1] != "1" {
				return false
			}
		case "Groups:":
			if seen[key] || len(parts) != 1 {
				return false
			}
		default:
			continue
		}
		seen[key] = true
	}
	return len(seen) == 9
}

func rootLocalParent(data []byte) bool {
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || parts[0] != "Uid:" {
			continue
		}
		if found || len(parts) != 5 || parts[1] != "0" || parts[2] != "0" || parts[3] != "0" || parts[4] != "0" {
			return false
		}
		found = true
	}
	return found
}

func guardLocalHandoff(host uint64, supervisor int, uid, gid uint32, kinds []localDescriptorKind, netAdmin bool, role string) error {
	if !validLocalIdentity(uid, gid) || host == 0 || supervisor <= 1 || os.Getppid() != supervisor || int64(os.Getuid()) != int64(uid) || int64(os.Geteuid()) != int64(uid) || int64(os.Getgid()) != int64(gid) || int64(os.Getegid()) != int64(gid) {
		return errLocalHandoff
	}
	// Check every inherited descriptor before opening /proc: a missing slot
	// must never be repopulated by our own validation reads.
	pinned, err := networkNamespaceInode(3)
	if err != nil || pinned == host {
		return errLocalHandoff
	}
	for i, kind := range kinds {
		fd := i + 4
		if !validLocalDescriptor(fd, kind) {
			return errLocalHandoff
		}
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Uid != 0 {
			return errLocalHandoff
		}
		if kind == localStream {
			peer, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if err != nil || peer.Uid != 0 || int64(peer.Pid) != int64(supervisor) {
				return errLocalHandoff
			}
		}
	}
	// Raw checks retain caller ownership and avoid finalizers on borrowed FDs.
	for i := range kinds {
		for j := 0; j < i; j++ {
			var a, b syscall.Stat_t
			if syscall.Fstat(i+4, &a) != nil || syscall.Fstat(j+4, &b) != nil || (a.Dev == b.Dev && a.Ino == b.Ino) {
				return errLocalHandoff
			}
		}
	}
	retained, err := syscall.Dup(3)
	if err != nil {
		return errLocalHandoff
	}
	syscall.CloseOnExec(retained)
	defer syscall.Close(retained)
	retainedID, err := networkNamespaceInode(retained)
	if err != nil || retainedID != pinned {
		return errLocalHandoff
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return errLocalHandoff
	}
	current, currentErr := networkNamespaceInode(int(self.Fd()))
	closeErr := self.Close()
	if currentErr != nil || closeErr != nil || current != pinned || current == host {
		return errLocalHandoff
	}
	statusFile, err := os.Open("/proc/self/status")
	if err != nil {
		return errLocalHandoff
	}
	status, readErr := io.ReadAll(io.LimitReader(statusFile, 64<<10+1))
	statusCloseErr := statusFile.Close()
	if readErr != nil || statusCloseErr != nil || len(status) > 64<<10 || !validLocalProcessStatus(status, uid, gid, netAdmin) {
		return errLocalHandoff
	}
	parent, err := os.Open("/proc/" + strconv.Itoa(supervisor) + "/status")
	if err != nil {
		return errLocalHandoff
	}
	parentStatus, parentReadErr := io.ReadAll(io.LimitReader(parent, 64<<10+1))
	parentCloseErr := parent.Close()
	if parentReadErr != nil || parentCloseErr != nil || len(parentStatus) > 64<<10 || !rootLocalParent(parentStatus) {
		return errLocalHandoff
	}
	if err := armParentDeath(host); err != nil || os.Getppid() != supervisor {
		return errLocalHandoff
	}
	return checkLocalRoleIsolation(role, os.ReadFile)
}

func GuardLocalAPI(host uint64, supervisor int, uid, gid uint32) error {
	return guardLocalHandoff(host, supervisor, uid, gid, apiDescriptorKinds, false, "gateway")
}

func GuardLocalHelper(host uint64, supervisor int, uid, gid uint32) error {
	return guardLocalHandoff(host, supervisor, uid, gid, helperDescriptorKinds, true, "gateway")
}

func GuardLocalProbe(host uint64, supervisor int, uid, gid uint32, side string) error {
	if side != "source" && side != "sink" {
		return errLocalHandoff
	}
	return guardLocalHandoff(host, supervisor, uid, gid, probeDescriptorKinds, false, side)
}
