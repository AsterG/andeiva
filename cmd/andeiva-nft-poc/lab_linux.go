package main

import (
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

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"github.com/AsterG/andeiva/internal/nftpoc"
)

func run(args []string) error {
	if handled, code := nftfixture.HandleRole(args); handled {
		if code != 0 {
			return exitCode(code)
		}
		return nil
	}
	if len(args) == 4 && args[0] == "--guardian" {
		return guardian(args[1], args[2], args[3])
	}
	if len(args) == 5 && args[0] == "--coordinator" {
		return coordinator(args[1], args[2], args[3], args[4])
	}
	if len(args) != 2 || args[0] != "--run-lab" || args[1] != "--snapshot-confirmed" {
		return errors.New("usage: andeiva-nft-poc --run-lab --snapshot-confirmed (authorized Debian 13 laboratory only)")
	}
	return laboratory()
}

type labReport struct {
	Run                    string            `json:"run"`
	Catalog                string            `json:"catalog"`
	Cases                  []string          `json:"passed_cases"`
	Probes                 int               `json:"probes"`
	ContinuousDeniedProbes int               `json:"continuous_denied_probes"`
	CommitNS               []int64           `json:"commit_ns"`
	Namespaces             map[string]uint64 `json:"namespaces"`
	ElapsedNS              int64             `json:"elapsed_ns"`
	CPUUS                  int64             `json:"cpu_us"`
	ChildrenCPUUS          int64             `json:"children_cpu_us"`
	MaxChildRSSKiB         int64             `json:"max_child_rss_kib"`
	StoreBytes             int64             `json:"store_bytes"`
	StateDirectory         string            `json:"state_directory"`
	HostUnchanged          bool              `json:"host_unchanged"`
	Cleanup                bool              `json:"cleanup"`
	Error                  string            `json:"error,omitempty"`
}

type controller struct {
	cmd *exec.Cmd
	ch  *channel
}

func (c *controller) stop() {
	if c == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	_ = c.ch.out.Close()
	_ = c.ch.input.Close()
}

func laboratory() (result error) {
	if os.Geteuid() != 0 {
		return errors.New("ANDEIVA_NFT_LAB_SUPERVISOR_REQUIRES_ROOT")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(release), "VERSION_ID=\"13\"") || !strings.Contains(string(release), "ID=debian") {
		return errors.New("ANDEIVA_NFT_REQUIRES_DEBIAN_13")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	runID := hex.EncodeToString(nonce[:])
	out, err := os.MkdirTemp("/var/tmp", "andeiva-nft-poc-")
	if err != nil {
		return err
	}
	state, err := os.MkdirTemp("/var/tmp", "andeiva-nft-state-")
	if err != nil {
		return err
	}
	if err = os.Chown(state, 1000, 1000); err != nil {
		return err
	}
	outputRoot, err := os.OpenRoot(out)
	if err != nil {
		return err
	}
	defer outputRoot.Close()
	log, err := outputRoot.OpenFile("operations.jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	report := labReport{Run: runID, Catalog: nftpoc.CatalogDigest, StateDirectory: state}
	started := time.Now()
	defer func() {
		report.ElapsedNS = time.Since(started).Nanoseconds()
		var own, kids syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &own)
		_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &kids)
		report.CPUUS = own.Utime.Sec*1000000 + own.Utime.Usec + own.Stime.Sec*1000000 + own.Stime.Usec
		report.ChildrenCPUUS = kids.Utime.Sec*1000000 + kids.Utime.Usec + kids.Stime.Sec*1000000 + kids.Stime.Usec
		report.MaxChildRSSKiB = kids.Maxrss
		_ = filepath.WalkDir(state, func(path string, d os.DirEntry, e error) error {
			if e == nil && !d.IsDir() {
				i, e := d.Info()
				if e == nil {
					report.StoreBytes += i.Size()
				}
			}
			return e
		})
		if result != nil {
			report.Error = result.Error()
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(out, "report.json"), append(b, '\n'), 0600)
		}
		if result == nil {
			result = e
		}
		fmt.Println(out)
	}()
	f, err := nftfixture.New(ctx, self, 1000, 1000)
	if err != nil {
		return err
	}
	report.Namespaces = f.NamespaceIDs()
	defer func() {
		if e := f.Close(); e != nil {
			result = errors.Join(result, e)
		} else {
			report.Cleanup = true
		}
	}()
	toRead, toWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer toRead.Close()
	defer toWrite.Close()
	fromRead, fromWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer fromRead.Close()
	defer fromWrite.Close()
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		return err
	}
	_, err = f.StartGateway(ctx, []string{"--guardian", runID, strconv.FormatUint(host, 10), strconv.Itoa(os.Getpid())}, toRead, fromWrite, log)
	if err != nil {
		return err
	}
	var c *controller
	defer func() { c.stop() }()
	var restart uint64
	start := func() error {
		restart++
		cmd, e := coordinatorCommand(ctx, runID, state, restart, host, report.Namespaces["gateway"])
		if e != nil {
			return e
		}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		cmd.ExtraFiles = []*os.File{toWrite, fromRead}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
		input, e := cmd.StdinPipe()
		if e != nil {
			return e
		}
		output, e := cmd.StdoutPipe()
		if e != nil {
			_ = input.Close()
			return e
		}
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			_ = input.Close()
			_ = output.Close()
			return e
		}
		c = &controller{cmd: cmd, ch: &channel{run: runID, out: input, input: output, in: scanner(output)}}
		return nil
	}
	if err = start(); err != nil {
		return err
	}
	status := func() (configpoc.Snapshot, error) {
		r, e := c.ch.call(message{Verb: "execute", Surface: configpoc.API, Request: configpoc.Request{Operation: configpoc.OpStatus}})
		return r.Snapshot, e
	}
	var key uint64
	execute := func(op string, cfg *configpoc.Config, ttl time.Duration) (configpoc.Snapshot, error) {
		s, e := status()
		if e != nil {
			return s, e
		}
		key++
		req := configpoc.Request{Operation: op, Key: fmt.Sprintf("lab-%d", key), ExpectedGeneration: s.Generation, Config: cfg, ConfirmFor: ttl}
		if op == configpoc.OpConfirm {
			req.Target = s.Running.Hash
		}
		begin := time.Now()
		r, e := c.ch.call(message{Verb: "execute", Surface: configpoc.CLI, Request: req})
		if op == configpoc.OpCommit && e == nil {
			report.CommitNS = append(report.CommitNS, time.Since(begin).Nanoseconds())
		}
		return r.Snapshot, e
	}
	probe := func(a, b bool) error {
		if e := f.CheckListeners(ctx); e != nil {
			return e
		}
		if e := f.CheckSentinel(ctx); e != nil {
			return e
		}
		for _, p := range []string{"tcp", "udp"} {
			for i, allowed := range []bool{a, b, false} {
				ok, e := f.Probe(ctx, p, 18080+i)
				report.Probes++
				if e != nil {
					return e
				}
				if ok != allowed {
					return fmt.Errorf("ANDEIVA_NFT_TRAFFIC_MISMATCH %s/%d want %v got %v", p, 18080+i, allowed, ok)
				}
			}
		}
		return f.CheckHost(ctx)
	}
	commit := func(cfg configpoc.Config, ttl time.Duration) error {
		if _, e := execute(configpoc.OpStage, &cfg, 0); e != nil {
			return e
		}
		_, e := execute(configpoc.OpCommit, nil, ttl)
		return e
	}
	if _, err = status(); err != nil {
		return err
	}
	if err = probe(false, false); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "default_deny_healthy_listeners")
	all := nftpoc.FixtureConfig(true, true, true, true)
	if err = commit(all, 0); err != nil {
		return err
	}
	if err = probe(true, true); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "tcp_udp_positive_and_always_denied")
	// Conflicting selectors prove kernel rule ordering, not just membership.
	for _, allowFirst := range []bool{false, true} {
		ordered := nftpoc.DefaultConfig()
		for _, protocol := range []string{"tcp", "udp"} {
			first, _ := nftpoc.RuleID(protocol + ".a")
			second, _ := nftpoc.RuleID(protocol + ".a.second")
			actions := []string{"deny", "allow"}
			if allowFirst {
				actions = []string{"allow", "deny"}
			}
			ordered.Rules = append(ordered.Rules, configpoc.Rule{ID: first, Action: actions[0]}, configpoc.Rule{ID: second, Action: actions[1]})
		}
		if err = commit(ordered, 0); err != nil {
			return err
		}
		if err = probe(allowFirst, false); err != nil {
			return err
		}
	}
	report.Cases = append(report.Cases, "tcp_udp_first_match_order")
	empty := nftpoc.DefaultConfig()
	if err = commit(empty, 0); err != nil {
		return err
	}
	if _, err = execute(configpoc.OpSave, nil, 0); err != nil {
		return err
	}
	a := nftpoc.FixtureConfig(true, true, false, false)
	if err = commit(a, 2*time.Second); err != nil {
		return err
	}
	// Coordinator is really killed; the separate authority and kernel remain alive.
	c.stop()
	c = nil
	time.Sleep(2500 * time.Millisecond)
	if err = probe(false, false); err != nil {
		return err
	}
	if err = start(); err != nil {
		return err
	}
	s, err := status()
	if err != nil {
		return err
	}
	if s.Running.Hash != s.Startup.Hash || s.Pending != nil || s.RecoveryRequired {
		return errors.New("ANDEIVA_NFT_RESTART_RECOVERY")
	}
	report.Cases = append(report.Cases, "confirmed_expiry_after_coordinator_sigkill", "controller_restart_same_kernel")
	if err = commit(a, 5*time.Second); err != nil {
		return err
	}
	if _, err = execute(configpoc.OpConfirm, nil, 0); err != nil {
		return err
	}
	if err = probe(true, false); err != nil {
		return err
	}
	s, err = status()
	if err != nil {
		return err
	}
	if s.Running.Hash == s.Startup.Hash || s.Pending != nil {
		return errors.New("ANDEIVA_NFT_STATE_SEPARATION")
	}
	report.Cases = append(report.Cases, "confirmed_commit", "running_startup_independent")
	if _, err = c.ch.call(message{Verb: "fail-next-component"}); err != nil {
		return err
	}
	b := nftpoc.FixtureConfig(false, false, true, true)
	if err = commit(b, 0); err == nil {
		return errors.New("ANDEIVA_NFT_FAULT_NOT_INJECTED")
	}
	if err = probe(true, false); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "real_nft_rollback_after_simulated_component_failure")
	bad := configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "not-in-catalog", Action: "allow"}}}
	if _, err = execute(configpoc.OpStage, &bad, 0); err == nil {
		return errors.New("ANDEIVA_NFT_INVALID_ACCEPTED")
	}
	if err = probe(true, false); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "invalid_catalog_rejected_without_change")
	s, err = status()
	if err != nil {
		return err
	}
	if _, err = c.ch.call(message{Verb: "concurrent", Request: configpoc.Request{Operation: configpoc.OpSave, Key: "concurrent", ExpectedGeneration: s.Generation}}); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "concurrent_generation_conflict")
	probeCtx, stopProbes := context.WithCancel(ctx)
	defer stopProbes()
	type probeResult struct {
		count int
		err   error
	}
	probeDone := make(chan probeResult, 1)
	go func() {
		count := 0
		for {
			for _, protocol := range []string{"tcp", "udp"} {
				if probeCtx.Err() != nil {
					probeDone <- probeResult{count, nil}
					return
				}
				ok, e := f.Probe(probeCtx, protocol, 18082)
				if probeCtx.Err() != nil {
					probeDone <- probeResult{count, nil}
					return
				}
				if e != nil || ok {
					probeDone <- probeResult{count, fmt.Errorf("ANDEIVA_NFT_TRANSIENT_PROBE: allowed=%v error=%v", ok, e)}
					return
				}
				count++
			}
		}
	}()
	for i := 0; i < 4; i++ {
		if err = commit(b, 0); err != nil {
			return err
		}
		if err = probe(false, true); err != nil {
			return err
		}
		if err = commit(a, 0); err != nil {
			return err
		}
		if err = probe(true, false); err != nil {
			return err
		}
	}
	stopProbes()
	continuous := <-probeDone
	if continuous.err != nil {
		return continuous.err
	}
	if continuous.count == 0 {
		return errors.New("ANDEIVA_NFT_NO_CONTINUOUS_PROBES")
	}
	report.ContinuousDeniedProbes = continuous.count
	report.Cases = append(report.Cases, "repeated_batch_readback_and_traffic", "continuous_always_denied_probes")
	r, err := c.ch.call(message{Verb: "history"})
	if err != nil || len(r.Audit) < 10 {
		return errors.New("ANDEIVA_NFT_AUDIT_MISSING")
	}
	report.Cases = append(report.Cases, "durable_audit")
	if err = f.CheckSentinel(ctx); err != nil {
		return err
	}
	if err = f.CheckListeners(ctx); err != nil {
		return err
	}
	report.Cases = append(report.Cases, "sentinel_preserved", "listeners_remain_healthy")
	if err = f.CheckHost(ctx); err != nil {
		return err
	}
	report.HostUnchanged = true
	return nil
}
