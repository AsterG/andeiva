//go:build linux

package configpoc

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

var reclaimOldReader = flag.String("reclaim-old-reader", "", "explicit qualified prior-source test binary")
var reclaimChild = flag.String("reclaim-child", "", "internal reclamation process-exit test boundary")
var reclaimArea = flag.String("reclaim-area", "", "internal reclamation process-exit test area")

func TestV2ReclaimProcessExit(t *testing.T) {
	if *reclaimChild != "" {
		if *reclaimChild != "before_reclaim_unlink" && *reclaimChild != "after_reclaim_unlink" && *reclaimChild != "after_reclaim_sync" {
			t.Fatal("invalid boundary")
		}
		area, err := os.OpenRoot(*reclaimArea)
		if err != nil {
			t.Fatal(err)
		}
		defer area.Close()
		s, err := openV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000})
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		if err = s.enableIndexReclamation(); err != nil {
			t.Fatal(err)
		}
		reclaimOrphanV2(t, s, "child-one")
		reclaimOrphanV2(t, s, "child-two")
		s.hook = func(point string) error {
			if point == *reclaimChild {
				os.Exit(23)
			}
			return nil
		}
		_, err = s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
		t.Fatal("child missed boundary", err)
	}
	for _, point := range []string{"before_reclaim_unlink", "after_reclaim_unlink", "after_reclaim_sync"} {
		t.Run(point, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			before := clone(s.state)
			if err := s.close(); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binary, "-test.run=^TestV2ReclaimProcessExit$", "-reclaim-child="+point, "-reclaim-area="+area.Name())
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("unexpected child: %v %s", err, output)
			}
			reopened, err := openV2(area, s.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close()
			if !reflect.DeepEqual(before, reopened.state) || reopened.reclaim != nil {
				t.Fatal("crash changed state/authority")
			}
			files := journalFiles(t, area.Name())
			if err = reopened.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			report, err := reopened.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
			if err != nil || !report.Complete || report.Removed != 0 || !reflect.DeepEqual(files, journalFiles(t, area.Name())) {
				t.Fatal("crash resumed deletion", report, err)
			}
		})
	}
}

// The supplied binary is built from the actual previous source, not a decoder
// that merely imitates it. Without that artifact this qualification is skipped.
func TestV2ReclaimOldReaderCompatibility(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply -reclaim-old-reader with qualified prior-source test binary")
	}
	for _, enabled := range []bool{false, true} {
		s, area, _, _ := v2Fixture(t, 64)
		if enabled {
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 130; i++ {
			if err := s.publish(clone(s.state)); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.close(); err != nil {
			t.Fatal(err)
		}
		before := journalFiles(t, area.Name())
		command := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name())
		output, err := command.CombinedOutput()
		want := "OLD_READER_ACCEPTED"
		if enabled {
			want = "OLD_READER_REJECTED"
		}
		if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("old reader compatibility: enabled=%v %v %s", enabled, err, output)
		}
	}
}
