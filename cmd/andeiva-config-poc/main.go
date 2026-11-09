// Command andeiva-config-poc runs an isolated experiment, never a traffic engine.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type report struct {
	Scope               string   `json:"scope"`
	Result              string   `json:"result"`
	Iterations          int      `json:"iterations"`
	Checks              []string `json:"checks"`
	ElapsedNS           int64    `json:"elapsed_ns"`
	CommitP50NS         int64    `json:"commit_p50_ns"`
	CommitP95NS         int64    `json:"commit_p95_ns"`
	CPUUS               int64    `json:"cpu_us"`
	PeakRSSBytes        int64    `json:"peak_rss_bytes"`
	CPUAvailable        bool     `json:"cpu_available"`
	HeapAllocBytes      uint64   `json:"heap_alloc_bytes"`
	TotalAllocatedBytes uint64   `json:"total_allocated_bytes"`
	StoreBytes          int64    `json:"store_bytes"`
	StoreFiles          int      `json:"store_files"`
	AuditRecords        int      `json:"audit_records"`
	RunningHash         string   `json:"running_hash"`
	StartupHash         string   `json:"startup_hash"`
	Limits              []string `json:"limits"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("andeiva-config-poc", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "new absolute state directory on a Linux filesystem")
	iterations := flags.Int("iterations", 20, "number of simulated commits (1..100)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !validStatePath(*stateDir) || *iterations < 1 || *iterations > 100 {
		fmt.Fprintln(stderr, "ANDEIVA_POC_INVALID_ARGUMENT")
		return 2
	}
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "ANDEIVA_POC_REQUIRES_UNPRIVILEGED_LINUX")
		return 2
	}
	// Never reuse or erase operator data. The caller chooses an already trusted parent.
	if err := os.Mkdir(*stateDir, 0700); err != nil {
		fmt.Fprintln(stderr, "ANDEIVA_POC_REQUIRES_NEW_DIRECTORY")
		return 2
	}
	r, err := experiment(*stateDir, *iterations)
	if err != nil {
		fmt.Fprintln(stderr, "ANDEIVA_POC_FAILED:", err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(r); err != nil {
		return 1
	}
	return 0
}

// The parent must remain trusted while the experiment runs; this is not a
// defense against another process replacing ancestors concurrently.
func validStatePath(dir string) bool {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(filepath.Separator) {
		return false
	}
	for part := filepath.Dir(dir); ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if part == filepath.Dir(part) {
			return true
		}
	}
}

func experiment(dir string, iterations int) (report, error) {
	r := report{Scope: "real_local_persistence_with_simulated_engines", Iterations: iterations,
		Limits: []string{"no_real_traffic_engines", "no_power_loss_test", "trusted_identity_fixture_only", "short_experiment_not_capacity_benchmark"}}
	started := time.Now()
	cpuBefore, _, cpuAvailable := processUsage()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	engines := []*configpoc.SimEngine{configpoc.NewSimEngine("sim-filter"), configpoc.NewSimEngine("sim-policy")}
	engineSet := []configpoc.Engine{engines[0], engines[1]}
	options := configpoc.Options{MaxRecords: 4096}
	s, err := configpoc.Open(dir, engineSet, options)
	if err != nil {
		return r, err
	}
	defer func() {
		if s != nil {
			_ = s.Close()
		}
	}()
	principal := configpoc.Principal{ID: "poc-admin", Role: configpoc.RoleAdmin}
	ctx := context.Background()
	var sequence int
	call := func(surface configpoc.Surface, request configpoc.Request) (configpoc.Snapshot, error) {
		current, e := s.Execute(ctx, principal, surface, configpoc.Request{Operation: configpoc.OpStatus})
		if e != nil {
			return configpoc.Snapshot{}, e
		}
		sequence++
		request.Key = fmt.Sprintf("experiment-%06d", sequence)
		request.ExpectedGeneration = current.Generation
		return s.Execute(ctx, principal, surface, request)
	}
	stage := func(id string, surface configpoc.Surface) error {
		c := configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: id, Action: "allow"}}}
		_, e := call(surface, configpoc.Request{Operation: configpoc.OpStage, Config: &c})
		if e != nil {
			return e
		}
		_, e = call(surface, configpoc.Request{Operation: configpoc.OpValidate})
		return e
	}
	latencies := make([]int64, 0, iterations)
	surfaces := []configpoc.Surface{configpoc.Web, configpoc.CLI, configpoc.API}
	var state configpoc.Snapshot
	for i := 0; i < iterations; i++ {
		surface := surfaces[i%len(surfaces)]
		if err = stage(fmt.Sprintf("rule-%03d", i), surface); err != nil {
			return r, err
		}
		before := time.Now()
		state, err = call(surface, configpoc.Request{Operation: configpoc.OpCommit})
		if err != nil {
			return r, err
		}
		latencies = append(latencies, time.Since(before).Nanoseconds())
		for _, engine := range engines {
			if engine.Current() != state.Running.Hash {
				return r, errors.New("simulated engine revision differs")
			}
		}
	}
	r.Checks = append(r.Checks, "ordered_commits_and_exact_simulated_engine_ack")
	if state.Running.Hash == state.Startup.Hash {
		return r, errors.New("running and startup unexpectedly equal before save")
	}
	state, err = call(configpoc.CLI, configpoc.Request{Operation: configpoc.OpSave})
	if err != nil {
		return r, err
	}
	saved := state.Startup.Hash
	if saved != state.Running.Hash {
		return r, errors.New("save did not preserve running revision")
	}
	r.Checks = append(r.Checks, "explicit_save")
	if err = stage("unsaved", configpoc.API); err != nil {
		return r, err
	}
	state, err = call(configpoc.API, configpoc.Request{Operation: configpoc.OpCommit})
	if err != nil {
		return r, err
	}
	unsaved := state.Running.Hash
	if err = s.Close(); err != nil {
		return r, err
	}
	s, err = configpoc.Open(dir, engineSet, options)
	if err != nil {
		return r, err
	}
	state, err = s.Execute(ctx, principal, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		return r, err
	}
	if state.Running.Hash != unsaved || state.Startup.Hash != saved {
		return r, errors.New("controller reopen changed saved state semantics")
	}
	r.Checks = append(r.Checks, "controller_reopen_preserves_unsaved_running")
	if err = s.Close(); err != nil {
		return r, err
	}
	options.Boot = true
	s, err = configpoc.Open(dir, engineSet, options)
	if err != nil {
		return r, err
	}
	state, err = s.Execute(ctx, principal, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		return r, err
	}
	if state.Running.Hash != saved || state.Startup.Hash != saved {
		return r, errors.New("simulated boot did not restore startup")
	}
	r.Checks = append(r.Checks, "simulated_boot_restores_startup_without_rebooting_machine")
	history, err := s.History(principal)
	if err != nil {
		return r, err
	}
	r.AuditRecords = len(history)
	r.RunningHash, r.StartupHash = state.Running.Hash, state.Startup.Hash
	if err = s.Close(); err != nil {
		return r, err
	}
	s = nil
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected state symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		r.StoreBytes += info.Size()
		r.StoreFiles++
		return nil
	})
	if err != nil {
		return r, err
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	r.CommitP50NS = latencies[(len(latencies)-1)/2]
	r.CommitP95NS = latencies[(len(latencies)*95+99)/100-1]
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	r.HeapAllocBytes = memoryAfter.HeapAlloc
	r.TotalAllocatedBytes = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
	cpuAfter, peakRSS, available := processUsage()
	r.CPUAvailable = cpuAvailable && available
	if r.CPUAvailable {
		r.CPUUS = cpuAfter - cpuBefore
		r.PeakRSSBytes = peakRSS
	}
	r.ElapsedNS = time.Since(started).Nanoseconds()
	r.Result = "PASS"
	return r, nil
}
