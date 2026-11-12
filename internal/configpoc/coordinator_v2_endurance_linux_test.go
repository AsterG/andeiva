//go:build linux

package configpoc

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type v2FixtureDiskUsage struct{ Bytes, Inodes, AllocatedFileBytes, AllocatedDirectoryBytes uint64 }

func coordinatorV2DiskUsage(t *testing.T, area *os.Root) v2FixtureDiskUsage {
	t.Helper()
	directory, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	allocated := func(info os.FileInfo) uint64 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Blocks < 0 {
			t.Fatal("unavailable allocated block accounting")
		}
		return uint64(stat.Blocks) * 512
	}
	var usage v2FixtureDiskUsage
	info, err := directory.Stat()
	if err != nil {
		t.Fatal(err)
	}
	usage.AllocatedDirectoryBytes = allocated(info)
	for {
		entries, e := directory.ReadDir(128)
		for _, entry := range entries {
			info, statErr := area.Lstat(entry.Name())
			if statErr != nil {
				t.Fatal(statErr)
			}
			size := info.Size()
			if size < 0 {
				t.Fatal("invalid file size")
			}
			usage.Bytes += uint64(size)
			usage.Inodes++
			usage.AllocatedFileBytes += allocated(info)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	return usage
}

func coordinatorV2Cycles(t *testing.T, cycles int) {
	t.Helper()
	c, area, engines, p, _ := coordinatorV2Fixture(t, true)
	initial, _, _ := c.status(p)
	initialRevision := initial.Running.Hash
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var startUsage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &startUsage); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	var first v2Operation
	for i := 0; i < cycles; i++ {
		stage := coordinatorV2Stage(t, c, p, fmt.Sprintf("cycle-%d", i))
		if i == 0 {
			first = stage.Operation
		}
		coordinatorV2Run(t, c, p, v2Request{Kind: OpValidate})
		seconds := uint64(30)
		committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
		coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Running.Hash})
		coordinatorV2Run(t, c, p, v2Request{Kind: OpSave})
		rolled := coordinatorV2Run(t, c, p, v2Request{Kind: OpRollback, Target: initialRevision})
		if rolled.Current.Running.Hash != initialRevision || rolled.Current.Firewall.Startup.Hash != committed.Current.Firewall.Running.Hash || rolled.Current.LocalServices.Startup.Hash != initial.LocalServices.Startup.Hash {
			t.Fatal("cycle lost independent Startup")
		}
		if c.store.state.ReservedBytes != 0 || c.store.state.ReservedInodes != 0 {
			t.Fatal("cycle leaked a lifecycle reservation")
		}
		if (i+1)%1000 == 0 {
			before := engines[0].applies.Load() + engines[1].applies.Load()
			var err error
			c, err = reopenCoordinatorV2(t, c, area)
			if err != nil {
				t.Fatal("cold cycle reopen", err)
			}
			if engines[0].applies.Load()+engines[1].applies.Load() != before {
				t.Fatal("quiescent reopen invented engine effects")
			}
			stored, e := c.store.lookup(p.Subject, first.ID)
			if e != nil || stored.Outcome == nil || stored.Outcome.Code != "applied" {
				t.Fatal("cold exact retained lookup", e)
			}
			t.Logf("completed_simulated_cycles=%d catalogue_operations=%d global_generation=%d", i+1, c.store.state.HighWater, c.store.state.Generation)
		}
	}
	state, generation, err := c.status(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.store.state.HighWater != uint64(cycles*6) || generation != uint64(1+cycles*5) || state.Firewall.Generation != uint64(9+cycles*5) || state.LocalServices.Generation != 27 || state.Pending != nil || state.Intent != nil {
		t.Fatal("cycle/projection accounting")
	}
	if engines[0].applies.Load() != int64(cycles*2) || engines[1].applies.Load() != int64(cycles*2) || engines[2].applies.Load() != 0 {
		t.Fatal("engine-effect count mismatch")
	}
	runtime.GC()
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	var usage syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	disk := coordinatorV2DiskUsage(t, area)
	t.Logf("fixture=simulated_controller_not_appliance cycles=%d catalogue_operations=%d simulated_apply_calls=%d logical_disk_bytes=%d allocated_file_bytes=%d allocated_directory_bytes=%d immutable_and_control_inodes=%d budget_bytes=%d budget_inodes=%d", cycles, c.store.state.HighWater, engines[0].applies.Load()+engines[1].applies.Load(), disk.Bytes, disk.AllocatedFileBytes, disk.AllocatedDirectoryBytes, disk.Inodes, c.store.budget.Bytes, c.store.budget.Inodes)
	t.Logf("process_max_rss_kib=%d baseline_heap_alloc_bytes=%d final_heap_alloc_bytes=%d baseline_heap_inuse_bytes=%d final_heap_inuse_bytes=%d baseline_sys_bytes=%d final_sys_bytes=%d", usage.Maxrss, baseline.HeapAlloc, final.HeapAlloc, baseline.HeapInuse, final.HeapInuse, baseline.Sys, final.Sys)
	cpu := func(value syscall.Timeval) float64 { return float64(value.Sec) + float64(value.Usec)/1000000 }
	t.Logf("elapsed_seconds=%.6f process_user_cpu_seconds=%.6f process_system_cpu_seconds=%.6f", elapsed.Seconds(), cpu(usage.Utime)-cpu(startUsage.Utime), cpu(usage.Stime)-cpu(startUsage.Stime))
	if cycles >= 5000 {
		t.Log("No real kernel rules or traffic were exercised. File cache/slab/cgroup memory are not process RSS. No reclamation or retention guarantee is qualified by this fixture.")
	}
}

func TestCoordinatorV2SimulatedCycles50(t *testing.T) { coordinatorV2Cycles(t, 50) }

func TestCoordinatorV2EngineEndurance5000(t *testing.T) {
	if os.Getenv("ANDEIVA_CONFIG_V2_ENGINE_ENDURANCE") != "1" {
		t.Skip("set ANDEIVA_CONFIG_V2_ENGINE_ENDURANCE=1 for the dedicated 5000 simulated engine-cycle qualification")
	}
	coordinatorV2Cycles(t, 5000)
}

// CPU/allocation microbenchmark only; it does not measure filesystem durability,
// engine application, appliance throughput or end-to-end transaction latency.
func BenchmarkCanonicalCompositeV2(b *testing.B) {
	config := v2CompositeConfig{SchemaVersion: 5, Domains: v2CompositeDomains{Firewall: v2ComponentReference{Schema: 4, Revision: strings.Repeat("a", 64)}, LocalServices: v2ComponentReference{Schema: 3, Revision: strings.Repeat("b", 64)}}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CanonicalComposite(config); err != nil {
			b.Fatal(err)
		}
	}
}
