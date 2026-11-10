//go:build linux

package localruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localchannel"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/nftfixture"
)

type Check struct {
	Ready                  bool              `json:"ready"`
	Run                    string            `json:"run"`
	Instance               string            `json:"instance"`
	Generation             uint64            `json:"generation"`
	ConfigGeneration       uint64            `json:"config_generation"`
	Namespaces             map[string]uint64 `json:"namespaces"`
	HelperPhase            string            `json:"helper_phase"`
	CurrentHash            string            `json:"current_hash"`
	ResetCount             int               `json:"reset_count"`
	SupervisorCapabilities string            `json:"supervisor_capabilities"`
}
type controlRequest struct {
	Operation string        `json:"operation"`
	Fault     string        `json:"fault,omitempty"`
	Probe     *ProbeRequest `json:"probe,omitempty"`
}
type controlReply struct {
	Status *Check       `json:"status,omitempty"`
	Probe  *ProbeResult `json:"probe,omitempty"`
	Error  string       `json:"error,omitempty"`
}
type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func waitChild(cmd *exec.Cmd) *child {
	c := &child{cmd: cmd, done: make(chan struct{})}
	go func() { c.err = cmd.Wait(); close(c.done) }()
	return c
}
func (c *child) stop() {
	if c == nil {
		return
	}
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.cmd.Process.Signal(syscall.SIGCONT)
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(15 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

type childEvent struct {
	role     string
	instance string
	event    event
}
type instance struct {
	fixture     *nftfixture.Fixture
	api, helper *child
	collector   *localobserve.Collector
	pin         *os.Process
	cancel      context.CancelFunc
	streams     []io.Closer
	workerDone  chan error
	failureMu   sync.Mutex
	failure     resetCause
}

func (i *instance) close() error {
	if i == nil {
		return nil
	}
	i.cancel()
	i.api.stop()
	i.helper.stop()
	for _, c := range i.streams {
		_ = c.Close()
	}
	if i.workerDone != nil {
		<-i.workerDone
	}
	var err error
	if i.collector != nil {
		err = errors.Join(err, i.collector.Close())
	}
	if i.pin != nil {
		err = errors.Join(err, i.pin.Release())
	}
	if i.fixture != nil {
		err = errors.Join(err, i.fixture.CloseOwned())
	}
	return err
}

type supervisor struct {
	mu     sync.Mutex
	state  Check
	active *instance
	dir    string
	config Config
	ids    identities
	reset  chan struct{}
	stop   context.CancelFunc
	probes int
}

func capabilityEvidence() (string, error) {
	b, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return "", e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:\t") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), nil
		}
	}
	return "", ErrUnavailable
}

func supervise(parent context.Context, dir string, out io.Writer) (result error) {
	if os.Geteuid() != 0 {
		return ErrUnavailable
	}
	config, ids, e := load(dir)
	if e != nil {
		return e
	}
	assets, e := openAssets(config.WebRoot)
	if e != nil {
		return e
	}
	if assets.Close() != nil {
		return ErrUnavailable
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	lock, e := root.OpenFile("supervisor.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Minute)
	defer cancel()
	lan, loop, e := bindRecovery(ctx, config)
	if e != nil {
		return e
	}
	defer lan.Close()
	defer loop.Close()
	cap, e := capabilityEvidence()
	if e != nil {
		return e
	}
	s := &supervisor{dir: dir, config: config, ids: ids, reset: make(chan struct{}, 1), stop: cancel, state: Check{SupervisorCapabilities: cap}}
	control, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "control.sock"), Net: "unix"})
	if e != nil {
		return e
	}
	defer control.Close()
	if os.Chmod(filepath.Join(dir, "control.sock"), 0600) != nil {
		return ErrUnavailable
	}
	controlDone := make(chan struct{})
	go func() { defer close(controlDone); s.serveControl(ctx, control) }()
	defer func() { cancel(); _ = control.Close(); <-controlDone }()
	events := make(chan childEvent, 32)
	logger := &eventsLog{out: out}
	defer func() {
		s.mu.Lock()
		s.state.Ready = false
		active := s.active
		s.active = nil
		s.mu.Unlock()
		result = errors.Join(result, active.close())
		_ = logger.write(map[string]any{"event": "stopped", "cleanup": result == nil})
	}()
	for generation := uint64(1); generation <= MaxResets+1; generation++ {
		s.mu.Lock()
		s.state.Ready = false
		s.state.ResetCount = int(generation - 1)
		s.state.Generation = generation
		s.mu.Unlock()
		i, l, e := startInstance(ctx, dir, config, ids, generation, lan, loop, events)
		if e != nil {
			_ = logger.write(map[string]any{"event": "start_failed", "generation": generation})
			if i != nil {
				if ce := i.close(); ce != nil {
					return ce
				}
			}
			return ErrUnavailable
		}
		s.mu.Lock()
		s.active = i
		s.state.Run = l.Binding.Run
		s.state.Instance = l.Binding.Instance
		s.state.Namespaces = i.fixture.NamespaceIDs()
		s.state.HelperPhase = "bootstrap"
		s.state.CurrentHash = ""
		s.mu.Unlock()
		if logger.write(map[string]any{"event": "started", "run": l.Binding.Run, "generation": generation, "supervisor_capabilities": cap}) != nil {
			return ErrUnavailable
		}
		restart := false
		for !restart {
			select {
			case <-ctx.Done():
				return nil
			case <-s.reset:
				i.noteFailure("supervisor", "operator_reset")
				restart = true
			case <-i.api.done:
				i.noteFailure("api", "process_exit")
				restart = true
			case <-i.helper.done:
				i.noteFailure("helper", "process_exit")
				restart = true
			case e := <-events:
				if e.instance != l.Binding.Instance {
					continue
				}
				s.mu.Lock()
				switch e.event.Event {
				case "failure":
					restart = true
				case "ready":
					s.state.Ready = true
					s.state.CurrentHash = e.event.Hash
					s.state.ConfigGeneration = e.event.Generation
				case "observed":
					s.state.Ready = true
					s.state.ConfigGeneration = e.event.Generation
					s.state.CurrentHash = e.event.Hash
				case "helper":
					s.state.HelperPhase = e.event.Phase
					if e.event.Phase == "blocked" {
						restart = true
					}
				}
				s.mu.Unlock()
			}
		}
		cause := i.resetCause()
		if logger.write(map[string]any{"event": "reset_requested", "generation": generation, "run": l.Binding.Run, "instance": l.Binding.Instance, "role": cause.Role, "reason": cause.Reason, "detected_at": cause.At}) != nil {
			return ErrUnavailable
		}
		s.mu.Lock()
		s.state.Ready = false
		s.active = nil
		s.mu.Unlock()
		if e = i.close(); e != nil {
			return e
		}
		// No old instance event or proof identity may make a replacement look ready.
		for len(events) > 0 {
			<-events
		}
		if logger.write(map[string]any{"event": "reset", "generation": generation, "cleanup": true, "role": cause.Role, "reason": cause.Reason}) != nil {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}

type eventsLog struct {
	mu  sync.Mutex
	out io.Writer
}

func (l *eventsLog) write(v map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	v["at"] = time.Now().UTC()
	return json.NewEncoder(l.out).Encode(v)
}

func startInstance(parent context.Context, dir string, c Config, ids identities, generation uint64, lan, loop *net.TCPListener, events chan<- childEvent) (i *instance, l launch, result error) {
	ctx, cancel := context.WithCancel(parent)
	i = &instance{cancel: cancel}
	self, e := os.Executable()
	if e != nil {
		return i, l, e
	}
	i.fixture, e = nftfixture.NewLocalOwned(ctx, self, ids.APIUID, ids.APIGID)
	if e != nil {
		return i, l, e
	}
	ns := i.fixture.NamespaceIDs()
	host, e := namespaceInode()
	if e != nil {
		return i, l, e
	}
	run, e := randomID()
	if e != nil {
		return i, l, e
	}
	id, e := randomID()
	if e != nil {
		return i, l, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return i, l, e
	}
	l = launch{Directory: dir, Config: c, IDs: ids, Binding: localchannel.Binding{Run: run, Instance: id, Generation: generation, Namespace: ns["gateway"], UID: ids.APIUID}, Host: host, BootID: strings.TrimSpace(string(boot))}
	apiTx, helperTx, e := pair()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, apiTx, helperTx)
	apiWorker, helperWorker, e := pair()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, apiWorker, helperWorker)
	helperCollector, parentCollector, e := pair()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, helperCollector, parentCollector)
	apiBoot, e := writeBootstrap(l)
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, apiBoot)
	helperBoot, e := writeBootstrap(l)
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, helperBoot)
	lanFD, e := lan.File()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, lanFD)
	loopFD, e := loop.File()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, loopFD)
	apiRead, apiWrite, e := os.Pipe()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, apiRead, apiWrite)
	helperRead, helperWrite, e := os.Pipe()
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, helperRead, helperWrite)
	cmd, e := i.fixture.LaunchLocalAPI(ctx, nftfixture.LocalAPIHandoff{UID: ids.APIUID, GID: ids.APIGID, RecoveryLAN: lanFD, RecoveryLoopback: loopFD, Transactions: apiTx, Listeners: apiWorker, Bootstrap: apiBoot}, apiWrite, io.Discard)
	if e != nil {
		return i, l, e
	}
	i.api = waitChild(cmd)
	for _, f := range []*os.File{lanFD, loopFD, apiTx, apiWorker, apiBoot, apiWrite} {
		if f.Close() != nil {
			return i, l, ErrUnavailable
		}
	}
	ready := make(chan struct{})
	go readEvents(ctx, "api", id, apiRead, events, ready, cancel, i.noteFailure)
	select {
	case <-ready:
	case <-i.api.done:
		return i, l, ErrUnavailable
	case <-time.After(5 * time.Second):
		return i, l, ErrUnavailable
	case <-ctx.Done():
		return i, l, ctx.Err()
	}
	// Separate retained process handle survives cmd.Wait and prevents PID reuse.
	i.pin, e = os.FindProcess(cmd.Process.Pid)
	if e != nil {
		return i, l, e
	}
	i.collector, e = localobserve.New(i.pin, localobserve.Expected{UID: ids.APIUID, GID: ids.APIGID, Namespace: ns["gateway"], HostNamespace: host, RunID: run, Instance: id, Generation: generation})
	if e != nil {
		return i, l, e
	}
	if _, e = i.collector.Observe(); e != nil {
		return i, l, e
	}
	collectorConn, e := net.FileConn(parentCollector)
	if e != nil {
		return i, l, e
	}
	i.streams = append(i.streams, collectorConn)
	if parentCollector.Close() != nil {
		return i, l, ErrUnavailable
	}
	i.workerDone = make(chan error, 1)
	go func() { i.workerDone <- localchannel.Serve(ctx, collectorConn, l.Binding, nil, i.collector) }()
	cmd, e = i.fixture.LaunchLocalHelper(ctx, run, nftfixture.LocalHelperHandoff{UID: ids.HelperUID, GID: ids.HelperGID, Transactions: helperTx, Listeners: helperWorker, Collector: helperCollector, Bootstrap: helperBoot}, helperWrite, io.Discard)
	if e != nil {
		return i, l, e
	}
	i.helper = waitChild(cmd)
	for _, f := range []*os.File{helperTx, helperWorker, helperCollector, helperBoot, helperWrite} {
		if f.Close() != nil {
			return i, l, ErrUnavailable
		}
	}
	go readEvents(ctx, "helper", id, helperRead, events, nil, cancel, i.noteFailure)
	return i, l, nil
}

func readEvents(ctx context.Context, role, instance string, r io.Reader, out chan<- childEvent, ready chan struct{}, cancel context.CancelFunc, note func(string, string)) {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 1024), 4096)
	signaled := false
	for scan.Scan() {
		var e event
		if firewallipc.Decode(scan.Bytes(), &e) != nil || (e.Event == "failure" && !validResetCause(role, e.Reason)) {
			note(role, "invalid_event")
			cancel()
			return
		}
		if e.Event == "failure" {
			note(role, e.Reason)
		}
		if role == "helper" && e.Event == "helper" && e.Phase == "blocked" {
			note(role, "guardian_blocked")
		}
		if e.Event == "worker-ready" && ready != nil && !signaled {
			close(ready)
			signaled = true
			continue
		}
		select {
		case out <- childEvent{role, instance, e}:
		case <-ctx.Done():
			return
		}
	}
	if ctx.Err() == nil {
		if scan.Err() != nil {
			note(role, "event_stream_error")
		} else {
			note(role, "event_stream_closed")
		}
	}
	cancel()
}
func namespaceInode() (uint64, error) {
	info, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		return 0, e
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Ino == 0 {
		return 0, ErrUnavailable
	}
	return s.Ino, nil
}

func (s *supervisor) serveControl(ctx context.Context, l *net.UnixListener) {
	slots := make(chan struct{}, 2)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer c.Close()
			if !rootPeer(c) || boundedConn(c) != nil {
				return
			}
			scan := bufio.NewScanner(c)
			scan.Buffer(make([]byte, 4096), maxBootstrap)
			if !scan.Scan() {
				return
			}
			var r controlRequest
			if firewallipc.Decode(scan.Bytes(), &r) != nil {
				return
			}
			reply := s.control(ctx, r)
			_ = json.NewEncoder(c).Encode(reply)
		}()
	}
}
func (s *supervisor) control(ctx context.Context, r controlRequest) controlReply {
	if r.Operation != "probe" && r.Probe != nil || r.Operation != "fault" && r.Fault != "" {
		return controlReply{Error: ErrUnavailable.Error()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Operation {
	case "check":
		v := s.state
		return controlReply{Status: &v}
	case "stop":
		s.stop()
		return controlReply{}
	case "reset":
		select {
		case s.reset <- struct{}{}:
		default:
		}
		return controlReply{}
	case "fault":
		if s.active == nil {
			return controlReply{Error: ErrUnavailable.Error()}
		}
		var target *child
		var signal syscall.Signal
		switch r.Fault {
		case "api-kill":
			target, signal = s.active.api, syscall.SIGKILL
		case "helper-kill":
			target, signal = s.active.helper, syscall.SIGKILL
		case "api-pause":
			target, signal = s.active.api, syscall.SIGSTOP
			s.state.Ready = false
		case "api-resume":
			target, signal = s.active.api, syscall.SIGCONT
		default:
			return controlReply{Error: ErrUnavailable.Error()}
		}
		if target == nil || target.cmd.Process.Signal(signal) != nil {
			return controlReply{Error: ErrUnavailable.Error()}
		}
		return controlReply{}
	case "probe":
		if s.active == nil || r.Probe == nil || s.probes >= 128 {
			return controlReply{Error: ErrUnavailable.Error()}
		}
		s.probes++
		v := s.probe(ctx, *r.Probe)
		return controlReply{Probe: &v}
	default:
		return controlReply{Error: ErrUnavailable.Error()}
	}
}
