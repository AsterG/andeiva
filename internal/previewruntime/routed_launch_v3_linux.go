//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const (
	RoutedHelperRoleV3  = "--andeiva-routed-helper-v3"
	RoutedAPIRoleV3     = "--andeiva-routed-api-v3"
	routedLaunchFrameV3 = 16384
	// Child construction/full inspection is distinct from the fixed effect RPC.
	routedLaunchStartupV3 = 45 * time.Second
)

// RoutedLaunchResourcesV3 contains exclusively supervisor-pinned resources.
// Callers retain every descriptor and own namespace teardown. This opt-in does
// not provision identities, storage, interfaces, listeners or deployed units.
type RoutedLaunchResourcesV3 struct {
	Metadata                          Metadata
	Identities                        Identities
	Gateway                           *os.File
	Management                        *os.File // Optional supervisor-owned HTTPS listener; API only.
	Host                              *os.File
	Directory                         *os.Root
	IntegrityRoot                     *os.Root // Optional pre-provisioned private helper-only root.
	Store, Admission, Plan, Emergency RoutedReaderRootV3
	Budget                            configpoc.SelectionReadBudgetV2
	StoreBudget                       configpoc.BudgetV2
}

type routedLaunchBootstrapV3 struct {
	Version     int                               `json:"version"`
	Integrity   bool                              `json:"integrity,omitempty"`
	Management  bool                              `json:"management,omitempty"`
	StoreBudget *configpoc.BudgetV2               `json:"store_budget,omitempty"`
	Metadata    Metadata                          `json:"metadata"`
	Identities  Identities                        `json:"identities"`
	Access      [4]recoveryreserve.ReaderAccessV2 `json:"access"`
	Profiles    [3]recoveryreserve.ProfileV2      `json:"profiles"`
	Budget      configpoc.SelectionReadBudgetV2   `json:"budget"`
	ParentPID   int                               `json:"parent_pid"`
	HelperPID   int32                             `json:"helper_pid"`
	Epoch       uint64                            `json:"epoch"`
}
type routedLaunchControlV3 struct {
	Epoch uint64 `json:"epoch"`
	PID   int32  `json:"pid"`
}
type routedLaunchEventV3 struct {
	Event string `json:"event"`
	Epoch uint64 `json:"epoch"`
	PID   int32  `json:"pid"`
}
type routedLaunchChildV3 struct {
	cmd       *exec.Cmd
	control   *os.File
	bootstrap *os.File
	events    chan routedLaunchEventV3
	done      chan struct{}
	readDone  chan struct{}
}

// RoutedLaunchSupervisorV3 keeps one helper incarnation across API restarts.
// Done signals helper loss or explicit closure; callers must then release their
// isolated namespace fixture. It never authorizes physical-host teardown.
type RoutedLaunchSupervisorV3 struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	resources   RoutedLaunchResourcesV3
	self        string
	stderr      io.Writer
	helper, api *routedLaunchChildV3
	epoch       uint64
	closed      bool
	blocked     bool
	done        chan struct{}
}

func validateRoutedLaunchV3(r RoutedLaunchResourcesV3) error {
	if r.Metadata.ValidateRouted() != nil || r.Identities.Validate() != nil || r.Gateway == nil || r.Host == nil || r.Directory == nil {
		return ErrIdentity
	}
	st, e := r.Gateway.Stat()
	if e != nil {
		return ErrIdentity
	}
	ns, ok := st.Sys().(*syscall.Stat_t)
	if !ok || ns.Ino != r.Metadata.GatewayNamespace {
		return ErrIdentity
	}
	st, e = r.Host.Stat()
	if e != nil {
		return ErrIdentity
	}
	ns, ok = st.Sys().(*syscall.Stat_t)
	if !ok || ns.Ino != r.Metadata.HostNamespace {
		return ErrIdentity
	}
	dir, e := r.Directory.Stat(".")
	if e != nil || !dir.IsDir() || dir.Mode().Perm() != 0750 || dir.Mode()&os.ModeSetgid != 0 {
		return ErrIdentity
	}
	ds, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || ds.Uid != r.Identities.HelperUID || ds.Gid != r.Identities.IPCGID {
		return ErrIdentity
	}
	seen := []os.FileInfo{dir}
	profiles := map[string]bool{}
	for i, item := range []RoutedReaderRootV3{r.Store, r.Admission, r.Plan, r.Emergency} {
		if item.Root == nil || item.Access.Version != 1 || item.Access.OwnerUID != r.Identities.APIUID || item.Access.ReaderGID == 0 || item.Access.ReaderGID == r.Identities.APIGID || item.Access.ReaderGID == r.Identities.IPCGID || item.Access.ReaderGID != r.Store.Access.ReaderGID || item.Access.CheckDirectory(item.Root) != nil {
			return ErrIdentity
		}
		info, e := item.Root.Stat(".")
		if e != nil {
			return ErrIdentity
		}
		for _, previous := range seen {
			if os.SameFile(previous, info) {
				return ErrIdentity
			}
		}
		seen = append(seen, info)
		if i > 0 {
			var role recoveryreserve.RoleV2
			var capacity int
			switch i {
			case 1:
				role, capacity = recoveryreserve.AdmissionV2, 4096
			case 2:
				role, capacity = recoveryreserve.PlanV2, 16384
			case 3:
				role, capacity = recoveryreserve.EmergencyV2, 8192
			default:
				return ErrIdentity
			}
			p := item.Profile
			if p.ID == "" || profiles[p.ID] || p.Role != role || p.Slots != 18 || p.Capacity != capacity {
				return ErrIdentity
			}
			profiles[p.ID] = true
		}
	}
	if r.IntegrityRoot != nil {
		file, err := r.IntegrityRoot.Open(".")
		if err != nil {
			return ErrIdentity
		}
		defer file.Close()
		if validateRoutedIntegrityDirectoryV3(file, r.Identities.HelperUID, r.Identities.IPCGID, seen) != nil {
			return ErrIdentity
		}
	}
	return nil
}

func trustedRoutedExecutableV3(path string) error {
	if !filepath.IsAbs(path) {
		return ErrIdentity
	}
	for current := path; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrIdentity
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return ErrIdentity
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return ErrIdentity
			}
		} else if !info.IsDir() {
			return ErrIdentity
		}
		if current == "/" {
			return nil
		}
	}
}

// StartRoutedLaunchV3 launches only fixed roles in the current trusted binary.
// That binary must dispatch them to RunRoutedLaunchRoleV3. The helper enters the
// pinned gateway; API remains in the host namespace with no capabilities. Unix
// sockets are created by the helper after dropping privileges, never by root.
func StartRoutedLaunchV3(ctx context.Context, r RoutedLaunchResourcesV3, stderr io.Writer) (*RoutedLaunchSupervisorV3, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || validateRoutedLaunchV3(r) != nil {
		return nil, ErrIdentity
	}
	host, e := namespaceID("/proc/self/ns/net")
	if e != nil || host != r.Metadata.HostNamespace {
		return nil, ErrIdentity
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return nil, ErrIdentity
	}
	actual, e := canonicalBoot(boot)
	if e != nil || actual != r.Metadata.BootID {
		return nil, ErrIdentity
	}
	self, e := os.Executable()
	if e != nil {
		return nil, ErrIdentity
	}
	self, e = filepath.EvalSymlinks(self)
	if e != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil {
		return nil, ErrIdentity
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &RoutedLaunchSupervisorV3{ctx: lifetime, cancel: cancel, resources: r, self: self, stderr: stderr, done: make(chan struct{})}
	s.helper, e = s.startChild(RoutedHelperRoleV3)
	if e == nil {
		e = s.sendBootstrap(s.helper, 0, 0)
	}
	if e == nil {
		e = s.helper.waitEvent(ctx, "helper_ready", 0)
	}
	if e == nil {
		e = s.RestartAPI(ctx)
	}
	if e != nil {
		_ = s.Close()
		return nil, e
	}
	go func() {
		select {
		case <-s.helper.done:
		case <-lifetime.Done():
		}
		cancel()
		_ = s.Close()
	}()
	return s, nil
}

func (s *RoutedLaunchSupervisorV3) bootstrap(helper int32, epoch uint64) routedLaunchBootstrapV3 {
	r := s.resources
	b := routedLaunchBootstrapV3{Version: 3, Integrity: r.IntegrityRoot != nil, Management: r.Management != nil, Metadata: r.Metadata, Identities: r.Identities, Access: [4]recoveryreserve.ReaderAccessV2{r.Store.Access, r.Admission.Access, r.Plan.Access, r.Emergency.Access}, Profiles: [3]recoveryreserve.ProfileV2{r.Admission.Profile, r.Plan.Profile, r.Emergency.Profile}, Budget: r.Budget, ParentPID: os.Getpid(), HelperPID: helper, Epoch: epoch}
	if r.StoreBudget != (configpoc.BudgetV2{}) {
		value := r.StoreBudget
		b.StoreBudget = &value
	}
	return b
}
func (s *RoutedLaunchSupervisorV3) sendBootstrap(c *routedLaunchChildV3, helper int32, epoch uint64) error {
	e := writeRoutedLaunchV3(c.bootstrap, s.bootstrap(helper, epoch))
	ce := c.bootstrap.Close()
	c.bootstrap = nil
	return errors.Join(e, ce)
}

func routedLaunchArgsV3(role, self string, ids Identities, reader uint32) (string, []string, error) {
	if ids.Validate() != nil || reader == 0 || reader == ids.APIGID || reader == ids.IPCGID || !filepath.IsAbs(self) {
		return "", nil, ErrIdentity
	}
	uid, gid, groups, caps := ids.APIUID, ids.APIGID, strconv.FormatUint(uint64(ids.IPCGID), 10), "-all"
	if role == RoutedHelperRoleV3 {
		uid, gid, groups, caps = ids.HelperUID, ids.IPCGID, strconv.FormatUint(uint64(reader), 10), "-all,+net_admin"
	} else if role != RoutedAPIRoleV3 {
		return "", nil, ErrIdentity
	}
	args := []string{"--reuid=" + strconv.FormatUint(uint64(uid), 10), "--regid=" + strconv.FormatUint(uint64(gid), 10), "--groups=" + groups, "--bounding-set=" + caps, "--inh-caps=" + caps, "--ambient-caps=" + caps, "--no-new-privs", "--", self, role}
	if role == RoutedHelperRoleV3 {
		return "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/setpriv"}, args...), nil
	}
	return "/usr/bin/setpriv", args, nil
}

func (s *RoutedLaunchSupervisorV3) startChild(role string) (*routedLaunchChildV3, error) {
	exe, args, e := routedLaunchArgsV3(role, s.self, s.resources.Identities, s.resources.Store.Access.ReaderGID)
	if e != nil {
		return nil, e
	}
	files := []*os.File{s.resources.Gateway}
	for _, root := range []*os.Root{s.resources.Directory, s.resources.Store.Root, s.resources.Admission.Root, s.resources.Plan.Root, s.resources.Emergency.Root} {
		f, e := root.Open(".")
		if e != nil {
			for _, old := range files[1:] {
				_ = old.Close()
			}
			return nil, e
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files[1:] {
			_ = f.Close()
		}
	}()
	bootR, bootW, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer bootR.Close()
	controlR, controlW, e := os.Pipe()
	if e != nil {
		_ = bootW.Close()
		return nil, e
	}
	defer controlR.Close()
	eventR, eventW, e := os.Pipe()
	if e != nil {
		_ = bootW.Close()
		_ = controlW.Close()
		return nil, e
	}
	defer eventW.Close()
	var cmd *exec.Cmd
	switch exe {
	case "/usr/bin/nsenter":
		// #nosec G204 -- Fixed executable; arguments contain only validated numeric identities, pinned namespace FD and the root-owned current binary with a fixed role, without a shell or administrative input.
		cmd = exec.CommandContext(s.ctx, "/usr/bin/nsenter", args...)
	case "/usr/bin/setpriv":
		// #nosec G204 -- Fixed executable; arguments contain only validated numeric identities and the root-owned current binary with a fixed role, without a shell or administrative input.
		cmd = exec.CommandContext(s.ctx, "/usr/bin/setpriv", args...)
	default:
		_ = bootW.Close()
		_ = controlW.Close()
		_ = eventR.Close()
		return nil, ErrIdentity
	}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.ExtraFiles = append(files, bootR, controlR, eventW, s.resources.Host)
	if role == RoutedHelperRoleV3 && s.resources.IntegrityRoot != nil {
		private, err := s.resources.IntegrityRoot.Open(".")
		if err != nil {
			_ = bootW.Close()
			_ = controlW.Close()
			_ = eventR.Close()
			return nil, err
		}
		defer private.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, private) // FD13 is never inherited by the API.
	}
	if role == RoutedAPIRoleV3 && s.resources.Management != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, s.resources.Management)
	}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = s.stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	c := &routedLaunchChildV3{cmd: cmd, control: controlW, bootstrap: bootW, events: make(chan routedLaunchEventV3, 4), done: make(chan struct{}), readDone: make(chan struct{})}
	started := make(chan error, 1)
	// Linux PDEATHSIG follows the creating OS thread, not merely its process.
	// Retain that thread until Wait reaps the child, including cancellation.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			_ = cmd.Wait()
		}
		close(c.done)
	}()
	if e = <-started; e != nil {
		_ = bootW.Close()
		_ = controlW.Close()
		_ = eventR.Close()
		return nil, e
	}
	go func() {
		defer close(c.readDone)
		defer close(c.events)
		defer eventR.Close()
		scan := bufio.NewScanner(eventR)
		scan.Buffer(make([]byte, 1024), routedLaunchFrameV3)
		for scan.Scan() {
			var event routedLaunchEventV3
			if firewallipc.Decode(scan.Bytes(), &event) != nil || int64(event.PID) != int64(cmd.Process.Pid) {
				return
			}
			select {
			case c.events <- event:
			case <-s.ctx.Done():
				return
			case <-c.done:
				return
			}
		}
	}()
	return c, nil
}

func writeRoutedLaunchV3(w *os.File, value any) error {
	if w == nil {
		return ErrUnavailable
	}
	data, e := json.Marshal(value)
	if e != nil || len(data) >= routedLaunchFrameV3 {
		return ErrUnavailable
	}
	if e = w.SetWriteDeadline(time.Now().Add(3 * time.Second)); e != nil {
		return e
	}
	data = append(data, '\n')
	n, e := w.Write(data)
	if e == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return e
}

func routedLaunchPIDV3(pid int) (int32, error) {
	if pid <= 1 || pid > math.MaxInt32 {
		return 0, ErrIdentity
	}
	return int32(pid), nil
}

func writeLocalRoutedEventV3(w *os.File, event string, epoch uint64) error {
	pid, err := routedLaunchPIDV3(os.Getpid())
	if err != nil {
		return err
	}
	return writeRoutedLaunchV3(w, routedLaunchEventV3{Event: event, Epoch: epoch, PID: pid})
}
func (c *routedLaunchChildV3) waitEvent(ctx context.Context, event string, epoch uint64) error {
	timer := time.NewTimer(routedLaunchStartupV3)
	defer timer.Stop()
	select {
	case got, ok := <-c.events:
		if ok && got.Event == event && got.Epoch == epoch {
			return nil
		}
		return ErrUnavailable
	case <-c.done:
		return ErrUnavailable
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrUnavailable
	}
}
func (c *routedLaunchChildV3) stop() {
	if c == nil {
		return
	}
	if c.bootstrap != nil {
		_ = c.bootstrap.Close()
		c.bootstrap = nil
	}
	_ = c.control.Close()
	select {
	case <-c.done:
	case <-time.After(4 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	<-c.readDone
}

// RestartAPI reaps the old writer before allowing the helper to drain its old
// channel. The new API is blocked on bootstrap until the helper acknowledges
// that drain. Its v3 handshake then fences the epoch before the store opens.
func (s *RoutedLaunchSupervisorV3) RestartAPI(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.blocked || s.ctx.Err() != nil || s.epoch == 0xffffffff {
		return ErrUnavailable
	}
	select {
	case <-s.helper.done:
		return ErrUnavailable
	default:
	}
	s.api.stop()
	s.api = nil
	c, e := s.startChild(RoutedAPIRoleV3)
	if e != nil {
		return e
	}
	s.api = c
	s.epoch++
	apiPID, apiErr := routedLaunchPIDV3(c.cmd.Process.Pid)
	helperPID, helperErr := routedLaunchPIDV3(s.helper.cmd.Process.Pid)
	if apiErr != nil || helperErr != nil {
		s.blocked = true
		c.stop()
		return ErrIdentity
	}
	if e = writeRoutedLaunchV3(s.helper.control, routedLaunchControlV3{Epoch: s.epoch, PID: apiPID}); e == nil {
		e = s.helper.waitEvent(ctx, "controller_ready", s.epoch)
	}
	if e == nil {
		e = s.sendBootstrap(c, helperPID, s.epoch)
	}
	if e == nil {
		e = c.waitEvent(ctx, "api_ready", s.epoch)
	}
	if e != nil {
		s.blocked = true
		c.stop()
		s.api = nil
	}
	return e
}
func (s *RoutedLaunchSupervisorV3) Done() <-chan struct{} { return s.done }
func (s *RoutedLaunchSupervisorV3) PIDs() (helper, api int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.helper != nil {
		helper = s.helper.cmd.Process.Pid
	}
	if s.api != nil {
		api = s.api.cmd.Process.Pid
	}
	return
}
func (s *RoutedLaunchSupervisorV3) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.api.stop()
	s.helper.stop()
	s.cancel()
	close(s.done)
	return nil
}
