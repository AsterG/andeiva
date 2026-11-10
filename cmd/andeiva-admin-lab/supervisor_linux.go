package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/nftfixture"
)

func run(args []string) error {
	if handled, code := nftfixture.HandleRole(args); handled {
		if code != 0 {
			return roleExit(code)
		}
		return nil
	}
	if len(args) == 4 && args[0] == "--guardian" {
		return helperProcess(args[1], args[2], args[3])
	}
	if len(args) == 7 && args[0] == "--api" {
		return apiProcess(args[1], args[2], args[3], args[4], args[5], args[6])
	}
	if len(args) == 1 && args[0] == "--provision" {
		dir, err := provision()
		if err == nil {
			fmt.Println(dir)
		}
		return err
	}
	if len(args) != 3 || args[0] != "--run-lab" || args[1] != "--snapshot-confirmed" {
		return errors.New("usage: andeiva-admin-lab --provision | --run-lab --snapshot-confirmed DIRECTORY")
	}
	return supervise(args[2])
}

type apiChild struct {
	cmd  *exec.Cmd
	done chan error
}

func (c *apiChild) stop() {
	if c != nil {
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

type report struct {
	Run            string           `json:"run"`
	Events         []map[string]any `json:"events"`
	Cleanup        bool             `json:"cleanup"`
	HostUnchanged  bool             `json:"host_unchanged"`
	ElapsedNS      int64            `json:"elapsed_ns"`
	CPUUS          int64            `json:"cpu_us"`
	ChildrenCPUUS  int64            `json:"children_cpu_us"`
	MaxChildRSSKiB int64            `json:"max_child_rss_kib"`
	Error          string           `json:"error,omitempty"`
}

func supervise(dir string) (result error) {
	if os.Geteuid() != 0 || validRunDirectory(dir) != nil {
		return errors.New("ANDEIVA_LAB_PRIVILEGE_OR_DIRECTORY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	base, err := os.OpenRoot("/var/tmp")
	if err != nil {
		return err
	}
	defer base.Close()
	root, err := base.OpenRoot(filepath.Base(dir))
	if err != nil {
		return err
	}
	defer root.Close()
	log, err := root.OpenFile("operations-"+id+".jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	report := report{Run: id, Events: []map[string]any{}}
	started := time.Now()
	emit := func(event map[string]any) {
		event["at"] = time.Now().UTC()
		report.Events = append(report.Events, event)
		_ = json.NewEncoder(os.Stdout).Encode(event)
	}
	defer func() {
		report.ElapsedNS = time.Since(started).Nanoseconds()
		var own, kids syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &own)
		_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &kids)
		report.CPUUS = own.Utime.Sec*1000000 + own.Utime.Usec + own.Stime.Sec*1000000 + own.Stime.Usec
		report.ChildrenCPUUS = kids.Utime.Sec*1000000 + kids.Utime.Usec + kids.Stime.Sec*1000000 + kids.Stime.Usec
		report.MaxChildRSSKiB = kids.Maxrss
		if result != nil {
			report.Error = result.Error()
		}
		data, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = writeOwned(filepath.Join(dir, "report-"+id+".json"), append(data, '\n'), 0600, 0, 0)
		}
		result = errors.Join(result, e)
	}()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	fixture, err := nftfixture.New(ctx, self, 1001, 1001)
	if err != nil {
		return err
	}
	defer func() { e := fixture.Close(); report.Cleanup = e == nil; result = errors.Join(result, e) }()
	if err = fixture.StartReverseListener(ctx); err != nil {
		return err
	}
	for _, protocol := range []string{"tcp", "udp"} {
		for port := 18080; port <= 18082; port++ {
			ok, e := fixture.ProbeReverseLocal(ctx, protocol, port)
			if e != nil || !ok {
				return errors.New("ANDEIVA_REVERSE_LISTENER_UNAVAILABLE")
			}
		}
	}
	requestR, requestW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer requestR.Close()
	defer requestW.Close()
	responseR, responseW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer responseR.Close()
	defer responseW.Close()
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		return err
	}
	helper, err := fixture.StartGateway(ctx, []string{"--guardian", id, strconv.FormatUint(host, 10), strconv.Itoa(os.Getpid())}, requestR, responseW, log)
	if err != nil {
		return err
	}
	helperDone := make(chan error, 1)
	go func() { helperDone <- helper.Wait() }()
	helperWaited := false
	defer func() {
		if !helperWaited {
			_ = helper.Process.Kill()
			<-helperDone
		}
	}()
	var api *apiChild
	defer func() { api.stop() }()
	var epoch uint64
	start := func(boot bool) error {
		epoch++
		args := []string{"--reuid=1001", "--regid=1001", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, "--api", dir, id, strconv.FormatUint(fixture.NamespaceIDs()["gateway"], 10), strconv.FormatUint(epoch, 10), strconv.FormatBool(boot), strconv.Itoa(os.Getpid())}
		cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", args...) // #nosec G204 G702 -- Fixed privilege dropper, fixture-verified root-owned self executable, validated lab directory and supervisor-generated arguments; no shell or remote input.
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		cmd.ExtraFiles = []*os.File{requestW, responseR}
		cmd.Stderr = log
		out, e := cmd.StdoutPipe()
		if e != nil {
			return e
		}
		if e = cmd.Start(); e != nil {
			_ = out.Close()
			return e
		}
		child := &apiChild{cmd: cmd, done: make(chan error, 1)}
		go func() { child.done <- cmd.Wait(); close(child.done) }()
		api = child
		ready := make(chan bool, 1)
		go func() { scan := bufio.NewScanner(out); ready <- scan.Scan() && scan.Text() == "ANDEIVA_ADMIN_READY" }()
		select {
		case ok := <-ready:
			if !ok {
				return errors.New("ANDEIVA_API_START_FAILED")
			}
		case <-time.After(15 * time.Second):
			return errors.New("ANDEIVA_API_START_TIMEOUT")
		}
		emit(map[string]any{"event": "api_ready", "epoch": epoch, "boot": boot, "url": adminOrigin, "namespaces": fixture.NamespaceIDs()})
		return nil
	}
	if err = start(true); err != nil {
		return err
	}
	commands := make(chan string)
	go func() {
		defer close(commands)
		scan := bufio.NewScanner(os.Stdin)
		scan.Buffer(make([]byte, 1024), 4096)
		for scan.Scan() {
			select {
			case commands <- scan.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		var apiDone <-chan error
		if api != nil {
			apiDone = api.done
		}
		select {
		case <-apiDone:
			api = nil
			emit(map[string]any{"event": "api_exited_helper_retained"})
		case <-helperDone:
			helperWaited = true
			api.stop()
			api = nil
			emit(map[string]any{"event": "helper_failure_emergency_close"})
			if e := fixture.CheckHost(ctx); e == nil {
				report.HostUnchanged = true
			}
			return errors.New("ANDEIVA_HELPER_EXITED_LAB_CLOSED")
		case <-ctx.Done():
			return ctx.Err()
		case command, ok := <-commands:
			if !ok || command == "stop" {
				if e := fixture.CheckHost(ctx); e != nil {
					return e
				}
				if e := fixture.CheckSentinel(ctx); e != nil {
					return e
				}
				report.HostUnchanged = true
				emit(map[string]any{"event": "stopped"})
				return nil
			}
			parts := strings.Fields(command)
			if len(parts) == 3 && (parts[0] == "probe" || parts[0] == "probe-reverse") {
				port, e := strconv.Atoi(parts[2])
				if e != nil || port < 18080 || port > 18082 || (parts[1] != "tcp" && parts[1] != "udp") {
					emit(map[string]any{"event": "invalid_command"})
					continue
				}
				local, e := fixture.ProbeLocal(ctx, parts[1], port)
				if parts[0] == "probe-reverse" {
					local, e = fixture.ProbeReverseLocal(ctx, parts[1], port)
				}
				if e != nil || !local {
					return errors.New("ANDEIVA_PROBE_LISTENER_UNHEALTHY")
				}
				var allowed bool
				if parts[0] == "probe" {
					allowed, e = fixture.Probe(ctx, parts[1], port)
				} else {
					allowed, e = fixture.ProbeReverse(ctx, parts[1], port)
				}
				if e != nil {
					return e
				}
				emit(map[string]any{"event": parts[0], "protocol": parts[1], "port": port, "allowed": allowed})
				continue
			}
			switch command {
			case "kill-api":
				api.stop()
				api = nil
				emit(map[string]any{"event": "api_killed"})
			case "restart-api":
				if api != nil {
					emit(map[string]any{"event": "api_already_running"})
					continue
				}
				if err = start(false); err != nil {
					return err
				}
			case "kill-helper":
				_ = helper.Process.Kill()
			case "status":
				if err = fixture.CheckHost(ctx); err != nil {
					return err
				}
				if err = fixture.CheckSentinel(ctx); err != nil {
					return err
				}
				emit(map[string]any{"event": "host_unchanged"})
			default:
				emit(map[string]any{"event": "invalid_command"})
			}
		}
	}
}
