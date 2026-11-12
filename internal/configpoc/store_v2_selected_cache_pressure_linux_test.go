//go:build linux

package configpoc

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

var selectedCachePressureChildV2 = flag.Bool("selected-cache-pressure-child", false, "run isolated selected-reader descriptor pressure test")

func TestSelectedCacheV2Pressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSelectedCacheV2PressureChild$", "-test.count=1", "-test.v", "-selected-cache-pressure-child")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestSelectedCacheV2PressureChild") {
		t.Fatalf("isolated pressure test: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}
func TestSelectedCacheV2PressureChild(t *testing.T) {
	if !*selectedCachePressureChildV2 {
		t.Skip("explicit child mode required")
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Max < 256 {
		t.Fatal("descriptor limit unavailable", err)
	}
	limit.Cur = 256
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	reader, _, _ := selectedReaderFixtureV2(t)
	if _, err := reader.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, ok := selectedCacheDescriptorCountV2()
	if !ok {
		t.Fatal("descriptor census")
	}
	v, err := reader.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	active, ok := selectedCacheDescriptorCountV2()
	if !ok {
		t.Fatal("active descriptor census")
	}
	t.Logf("soft=256 base=%d cache_cap=%d retained=%d active=%d", before, v.graph.cache.files, len(v.graph.cache.entries), active)
	if active > 224 || len(v.graph.cache.entries) > v.graph.cache.files {
		t.Fatal("transient descriptor headroom lost")
	}
	if err = v.graph.cache.close(v.graph); err != nil {
		t.Fatal(err)
	}
	after, ok := selectedCacheDescriptorCountV2()
	if !ok || after != before {
		t.Fatal("reader leaked descriptors", before, after)
	}
	var held []*os.File
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()
	exhausted := false
	for range 256 {
		f, e := os.Open("/dev/null")
		if errors.Is(e, syscall.EMFILE) {
			exhausted = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, f)
	}
	if !exhausted {
		t.Fatal("pressure not reached")
	}
	if _, err = reader.Observe(context.Background()); err == nil {
		t.Fatal("partial authority returned under descriptor exhaustion")
	}
	for _, f := range held {
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	held = nil
	if _, err = reader.Observe(context.Background()); err != nil {
		t.Fatal("reader did not recover after caller released descriptors", err)
	}
	after, ok = selectedCacheDescriptorCountV2()
	if !ok || after != before {
		t.Fatal("failed read leaked descriptors", before, after)
	}
}
