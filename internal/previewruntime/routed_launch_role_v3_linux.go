//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

// Context resources are borrowed for this child lifetime. Factories may read
// their trusted deployment configuration, but cannot replace these descriptors,
// invent a peer identity or open a configuration writer before the V3 factory.
type RoutedLaunchContextV3 struct {
	LocalOrigin                *RoutedLocalOriginV3
	Integrity                  bool
	IntegrityRoot              *os.Root // Helper only; always nil in the API role.
	Management                 *os.File // API only; borrowed supervisor listener.
	Metadata                   Metadata
	Identities                 Identities
	Gateway, Host              *os.File
	Store                      *os.Root
	Access                     recoveryreserve.ReaderAccessV2
	Admission, Plan, Emergency RoutedReaderRootV3
	Budget                     configpoc.SelectionReadBudgetV2
	StoreBudget                configpoc.BudgetV2
	Epoch                      uint64
	PeerPID                    int32
}
type RoutedHelperComponentsV3 struct {
	NetworkInventory func(context.Context) (networkinventory.Snapshot, error)
	Authority        configpoc.RoutedAuthorityV1
	Compatibility    *SessionV2
	Cleanup          io.Closer
}
type RoutedLaunchFactoriesV3 struct {
	Helper func(context.Context, RoutedLaunchContextV3) (RoutedHelperComponentsV3, error)
	API    func(context.Context, RoutedLaunchContextV3) (OperationsRuntimeOptionsV2, io.Closer, error)
	// ServeAPI binds the trusted HTTPS listener after boot/resume and readback,
	// then calls ready exactly once before serving. It must return promptly when
	// ctx is cancelled. Listener/TLS failure must never call ready.
	ServeAPI func(context.Context, *RoutedOperationsRuntimeV3, func() error) error
}

type routedLaunchFilesV3 struct {
	managementFile *os.File
	integrityFile  *os.File
	integrityRoot  *os.Root
	files          [10]*os.File
	roots          [5]*os.Root
}

func (f *routedLaunchFilesV3) close() {
	if f.managementFile != nil {
		_ = f.managementFile.Close()
	}
	if f.integrityRoot != nil {
		_ = f.integrityRoot.Close()
	}
	if f.integrityFile != nil {
		_ = f.integrityFile.Close()
	}
	for _, r := range f.roots {
		if r != nil {
			_ = r.Close()
		}
	}
	for _, file := range f.files {
		if file != nil {
			_ = file.Close()
		}
	}
}

// FD3 gateway, FD4 private socket directory, FD5-8 selected store/reserves,
// FD9 root bootstrap, FD10 control, FD11 events, FD12 host namespace pin.
func receiveRoutedLaunchV3(role string) (*routedLaunchFilesV3, routedLaunchBootstrapV3, error) {
	var b routedLaunchBootstrapV3
	f := &routedLaunchFilesV3{}
	fail := func() (*routedLaunchFilesV3, routedLaunchBootstrapV3, error) { f.close(); return nil, b, ErrIdentity }
	seen := map[[2]uint64]bool{}
	for i := range f.files {
		fd := i + 3
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return fail()
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if e != nil {
			return fail()
		}
		id := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[id] {
			return fail()
		}
		seen[id] = true
		switch {
		case i == 0 || i == 9:
			var fs unix.Statfs_t
			kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.NS_GET_NSTYPE, 0)
			if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || errno != 0 || kind != unix.CLONE_NEWNET || flags&unix.O_ACCMODE != unix.O_RDONLY {
				return fail()
			}
		case i >= 1 && i <= 5:
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || flags&unix.O_ACCMODE != unix.O_RDONLY {
				return fail()
			}
		default:
			want := unix.O_RDONLY
			if i == 8 {
				want = unix.O_WRONLY
			}
			if st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Uid != 0 || flags&unix.O_ACCMODE != want {
				return fail()
			}
			if unix.SetNonblock(fd, true) != nil {
				return fail()
			}
		}
		f.files[i] = os.NewFile(uintptr(fd), fmt.Sprintf("routed-launch-%d", fd))
		if f.files[i] == nil {
			return fail()
		}
		unix.CloseOnExec(fd)
	}
	if e := f.files[6].SetReadDeadline(time.Now().Add(15 * time.Second)); e != nil {
		return fail()
	}
	scan := bufio.NewScanner(f.files[6])
	scan.Buffer(make([]byte, 1024), routedLaunchFrameV3)
	if !scan.Scan() || firewallipc.Decode(scan.Bytes(), &b) != nil || b.Version != 3 || b.ParentPID <= 1 || os.Getppid() != b.ParentPID {
		return fail()
	}
	if scan.Scan() || scan.Err() != nil {
		return fail()
	}
	parent, e := os.Stat(fmt.Sprintf("/proc/%d", b.ParentPID))
	if e != nil {
		return fail()
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return fail()
	}
	parentStatus, e := os.Open(fmt.Sprintf("/proc/%d/status", b.ParentPID))
	if e != nil {
		return fail()
	}
	status, readErr := io.ReadAll(io.LimitReader(parentStatus, 65537))
	closeErr := parentStatus.Close()
	if readErr != nil || closeErr != nil || !rootRoutedParentStatusV3(status, b.ParentPID) || os.Getppid() != b.ParentPID {
		return fail()
	}
	if e = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0); e != nil || os.Getppid() != b.ParentPID {
		return fail()
	}
	if (b.LocalOrigin != nil && validateRoutedLocalOriginV3(b.LocalOrigin) != nil) || (b.Metadata.SchemaVersion == RoutedMetadataSchemaVersion && b.LocalOrigin == nil) || b.Metadata.ValidateRouted() != nil || b.Identities.Validate() != nil {
		return fail()
	}
	if role == RoutedHelperRoleV3 {
		if b.Epoch != 0 || b.HelperPID != 0 {
			return fail()
		}
	} else if role != RoutedAPIRoleV3 || b.Epoch == 0 || b.Epoch > 0xffffffff || b.HelperPID <= 1 {
		return fail()
	}
	// Adopt FD13 before opening any roots: those opens may reuse an absent FD13.
	if b.Integrity && role == RoutedHelperRoleV3 {
		f.integrityFile = os.NewFile(13, "routed-integrity-root")
		var other []os.FileInfo
		for _, item := range f.files {
			info, err := item.Stat()
			if err != nil {
				return fail()
			}
			other = append(other, info)
		}
		if validateRoutedIntegrityDirectoryV3(f.integrityFile, b.Identities.HelperUID, b.Identities.IPCGID, other) != nil {
			return fail()
		}
		unix.CloseOnExec(13)
		private, err := os.OpenRoot("/proc/self/fd/13")
		if err != nil {
			return fail()
		}
		f.integrityRoot = private
		before, err := f.integrityFile.Stat()
		after, ae := private.Stat(".")
		if err != nil || ae != nil || !os.SameFile(before, after) {
			return fail()
		}
	}
	if b.Management && role == RoutedAPIRoleV3 {
		var st unix.Stat_t
		if unix.Fstat(13, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return fail()
		}
		f.managementFile = os.NewFile(13, "routed-management-listener")
		if f.managementFile == nil {
			return fail()
		}
		unix.CloseOnExec(13)
	}
	for i := range f.roots {
		r, e := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", i+4))
		if e != nil {
			return fail()
		}
		f.roots[i] = r
		before, e := f.files[i+1].Stat()
		after, ae := r.Stat(".")
		if e != nil || ae != nil || !os.SameFile(before, after) {
			return fail()
		}
	}
	resources := RoutedLaunchResourcesV3{Metadata: b.Metadata, Identities: b.Identities, Gateway: f.files[0], Host: f.files[9], Directory: f.roots[0], IntegrityRoot: f.integrityRoot, Store: RoutedReaderRootV3{Root: f.roots[1], Access: b.Access[0]}, Admission: RoutedReaderRootV3{Root: f.roots[2], Access: b.Access[1], Profile: b.Profiles[0]}, Plan: RoutedReaderRootV3{Root: f.roots[3], Access: b.Access[2], Profile: b.Profiles[1]}, Emergency: RoutedReaderRootV3{Root: f.roots[4], Access: b.Access[3], Profile: b.Profiles[2]}, Budget: b.Budget}
	if validateRoutedLaunchV3(resources) != nil {
		return fail()
	}
	actual, e := namespaceID("/proc/self/ns/net")
	if e != nil {
		return fail()
	}
	if role == RoutedHelperRoleV3 {
		groups, e := os.Getgroups()
		status, se := os.ReadFile("/proc/self/status")
		if e != nil || se != nil || actual != b.Metadata.GatewayNamespace || routedHelperProcessFieldsV3(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, string(status), b.Identities, b.Access[0].ReaderGID) != nil {
			return fail()
		}
	} else if actual != b.Metadata.HostNamespace || checkPrivileges(b.Identities, false) != nil {
		return fail()
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return fail()
	}
	actualBoot, e := canonicalBoot(boot)
	if e != nil || actualBoot != b.Metadata.BootID {
		return fail()
	}
	return f, b, nil
}

func rootRoutedParentStatusV3(data []byte, pid int) bool {
	if len(data) == 0 || len(data) > 65536 || pid <= 1 {
		return false
	}
	seenPID, seenUID := false, false
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Pid":
			if seenPID || strings.TrimSpace(value) != strconv.Itoa(pid) {
				return false
			}
			seenPID = true
		case "Uid":
			values := strings.Fields(value)
			if seenUID || len(values) != 4 {
				return false
			}
			for _, value := range values {
				if value != "0" {
					return false
				}
			}
			seenUID = true
		}
	}
	return seenPID && seenUID
}
func (f *routedLaunchFilesV3) context(b routedLaunchBootstrapV3) RoutedLaunchContextV3 {
	value := configpoc.BudgetV2{}
	if b.StoreBudget != nil {
		value = *b.StoreBudget
	}
	return RoutedLaunchContextV3{LocalOrigin: cloneRoutedLocalOriginV3(b.LocalOrigin), StoreBudget: value, Integrity: b.Integrity, IntegrityRoot: f.integrityRoot, Management: f.managementFile, Metadata: b.Metadata, Identities: b.Identities, Gateway: f.files[0], Host: f.files[9], Store: f.roots[1], Access: b.Access[0], Admission: RoutedReaderRootV3{Root: f.roots[2], Access: b.Access[1], Profile: b.Profiles[0]}, Plan: RoutedReaderRootV3{Root: f.roots[3], Access: b.Access[2], Profile: b.Profiles[1]}, Emergency: RoutedReaderRootV3{Root: f.roots[4], Access: b.Access[3], Profile: b.Profiles[2]}, Budget: b.Budget, Epoch: b.Epoch, PeerPID: b.HelperPID}
}

// RunRoutedLaunchRoleV3 handles only the two fixed, root-launched child roles.
// It closes adopted descriptors on return; the role process must then exit.
// Ordinary HTTP/CLI requests
// cannot invoke it or supply a factory, descriptor, peer PID or executable.
func RunRoutedLaunchRoleV3(ctx context.Context, role string, factories RoutedLaunchFactoriesV3) error {
	if ctx == nil || ctx.Err() != nil || (role != RoutedHelperRoleV3 && role != RoutedAPIRoleV3) {
		return ErrIdentity
	}
	f, b, e := receiveRoutedLaunchV3(role)
	if e != nil {
		return e
	}
	defer f.close()
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	if role == RoutedHelperRoleV3 {
		return runRoutedHelperLaunchV3(lifetime, cancel, f, b, factories)
	}
	// Parent closing control is a normal management stop. Root death separately
	// kills this child; the helper retains its guardian during API-only restart.
	go func() { var value [1]byte; _, _ = f.files[7].Read(value[:]); cancel() }()
	return runRoutedAPILaunchV3(lifetime, f, b, factories)
}

func runRoutedAPILaunchV3(ctx context.Context, f *routedLaunchFilesV3, b routedLaunchBootstrapV3, factories RoutedLaunchFactoriesV3) (result error) {
	if factories.API == nil || factories.ServeAPI == nil {
		return ErrConfiguration
	}
	o, cleanup, e := factories.API(ctx, f.context(b))
	if cleanup != nil {
		defer func() { result = errors.Join(result, cleanup.Close()) }()
	}
	if e != nil {
		return e
	}
	if o.Store != f.roots[1] || o.Runtime.SharedReader == nil || *o.Runtime.SharedReader != b.Access[0] || o.Runtime.BootID != b.Metadata.BootID || !o.Runtime.GuardDeadlines {
		return ErrIdentity
	}
	routed, e := dialRoutedLaunchV3(ctx, f.roots[0], "routed.sock", b)
	if e != nil {
		return e
	}
	legacy, e := dialRoutedLaunchV3(ctx, f.roots[0], "compat.sock", b)
	if e != nil {
		_ = routed.Close()
		return e
	}
	open := OpenRoutedOperationsRuntimeV3
	if b.Integrity {
		open = OpenRoutedIntegrityOperationsRuntimeV3
	}
	runtime, e := open(ctx, b.Metadata, b.Identities, routed, legacy, b.HelperPID, b.HelperPID, o)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, runtime.Close()) }()
	var mu sync.Mutex
	signaled := false
	ready := func() error {
		mu.Lock()
		defer mu.Unlock()
		if signaled || ctx.Err() != nil {
			return ErrUnavailable
		}
		signaled = true
		return writeLocalRoutedEventV3(f.files[8], "api_ready", b.Epoch)
	}
	return factories.ServeAPI(ctx, runtime, ready)
}

func dialRoutedLaunchV3(ctx context.Context, directory *os.Root, name string, b routedLaunchBootstrapV3) (*net.UnixConn, error) {
	if name != "routed.sock" && name != "compat.sock" {
		return nil, ErrIdentity
	}
	before, e := directory.Lstat(name)
	if e != nil || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0660 {
		return nil, ErrIdentity
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != b.Identities.HelperUID || st.Gid != b.Identities.IPCGID {
		return nil, ErrIdentity
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	c, e := dialer.DialContext(ctx, "unix", "/proc/self/fd/4/"+name)
	if e != nil {
		return nil, ErrUnavailable
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, ErrIdentity
	}
	after, e := directory.Lstat(name)
	if e != nil || !os.SameFile(before, after) || inheritedPeerV2(u, b.Identities.HelperUID, b.Identities.IPCGID, b.HelperPID) != nil {
		_ = u.Close()
		return nil, ErrIdentity
	}
	return u, nil
}

type routedLaunchServersV3 struct {
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.Mutex
	connections []*net.UnixConn
}

func (s *routedLaunchServersV3) drain() {
	if s == nil {
		return
	}
	s.cancel()
	s.mu.Lock()
	for _, c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	<-s.done
}

func runRoutedHelperLaunchV3(ctx context.Context, cancel context.CancelFunc, f *routedLaunchFilesV3, b routedLaunchBootstrapV3, factories RoutedLaunchFactoriesV3) (result error) {
	if factories.Helper == nil {
		return ErrConfiguration
	}
	c, e := factories.Helper(ctx, f.context(b))
	if c.Cleanup != nil {
		defer func() { result = errors.Join(result, c.Cleanup.Close()) }()
	}
	if e != nil {
		return e
	}
	if c.Authority == nil || c.Compatibility == nil || !c.Compatibility.readOnly || c.Compatibility.base == nil || c.Compatibility.base.namespace != b.Metadata.GatewayNamespace {
		return ErrIdentity
	}
	owner, ok := c.Authority.(*RoutedAuthority)
	if !ok || owner == nil || c.Compatibility.routedOwner != owner || c.Compatibility.routedReadback == nil {
		return ErrIdentity
	}
	o := RoutedHelperOptionsV3{NetworkInventory: c.NetworkInventory, IntegrityRoot: f.integrityRoot, Store: f.roots[1], Access: b.Access[0], Admission: RoutedReaderRootV3{Root: f.roots[2], Access: b.Access[1], Profile: b.Profiles[0]}, Plan: RoutedReaderRootV3{Root: f.roots[3], Access: b.Access[2], Profile: b.Profiles[1]}, Emergency: RoutedReaderRootV3{Root: f.roots[4], Access: b.Access[3], Profile: b.Profiles[2]}, Budget: b.Budget, Authority: c.Authority}
	runtime, e := OpenRoutedHelperV3(ctx, b.Metadata, b.Identities, o)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, runtime.Close()) }()
	var listeners [2]*net.UnixListener
	for i, name := range []string{"routed.sock", "compat.sock"} {
		path := "/proc/self/fd/4/" + name
		l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			return e
		}
		listeners[i] = l
		defer l.Close()
		// #nosec G302 -- Unix socket only, in the pinned private helper-owned IPC directory; the dedicated API group needs connect permission.
		if e = os.Chmod(path, 0660); e != nil {
			return e
		}
	}
	if e = writeLocalRoutedEventV3(f.files[8], "helper_ready", 0); e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() {
		for _, l := range listeners {
			_ = l.Close()
		}
		_ = f.files[7].Close()
	})
	defer stop()
	var active *routedLaunchServersV3
	defer func() { cancel(); active.drain() }()
	scan := bufio.NewScanner(f.files[7])
	scan.Buffer(make([]byte, 1024), routedLaunchFrameV3)
	var epoch uint64
	for scan.Scan() {
		var request routedLaunchControlV3
		if firewallipc.Decode(scan.Bytes(), &request) != nil || request.Epoch != epoch+1 || request.Epoch > 0xffffffff || request.PID <= 1 {
			return ErrIdentity
		}
		active.drain()
		active = nil
		epoch = request.Epoch
		// Drain closes sockets but never cancels an in-flight effect's context;
		// Serve retains the helper lifetime until its dispatch and reply finish.
		if e = writeLocalRoutedEventV3(f.files[8], "controller_ready", epoch); e != nil {
			return e
		}
		active = startRoutedLaunchServersV3(ctx, listeners, runtime, c.Compatibility, b, request.PID)
	}
	if ctx.Err() != nil {
		return nil
	}
	return scan.Err()
}

func startRoutedLaunchServersV3(ctx context.Context, listeners [2]*net.UnixListener, runtime *RoutedHelperRuntimeV3, compatibility *SessionV2, b routedLaunchBootstrapV3, pid int32) *routedLaunchServersV3 {
	acceptCtx, cancel := context.WithCancel(ctx)
	s := &routedLaunchServersV3{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for i, listener := range listeners {
			workers.Add(1)
			go func(i int, l *net.UnixListener) {
				defer workers.Done()
				for attempts := 0; attempts < 8; attempts++ {
					if acceptCtx.Err() != nil {
						return
					}
					_ = l.SetDeadline(time.Now().Add(250 * time.Millisecond))
					connection, e := l.AcceptUnix()
					if e != nil {
						if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
							attempts--
							continue
						}
						return
					}
					if inheritedPeerV2(connection, b.Identities.APIUID, b.Identities.APIGID, pid) != nil {
						_ = connection.Close()
						continue
					}
					s.mu.Lock()
					if acceptCtx.Err() != nil {
						s.mu.Unlock()
						_ = connection.Close()
						return
					}
					s.connections = append(s.connections, connection)
					s.mu.Unlock()
					if i == 0 {
						_ = runtime.Serve(ctx, connection, pid)
					} else {
						_ = compatibility.ServeInheritedV2(ctx, connection, b.Identities.APIUID, b.Identities.APIGID, pid, b.Metadata.RunID)
					}
					return
				}
			}(i, listener)
		}
	}()
	return s
}
