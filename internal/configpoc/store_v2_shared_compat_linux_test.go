//go:build linux

package configpoc

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestSharedProfileV2OldReaderCompatibility(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply -reclaim-old-reader with a qualified prior-source test binary; skip is not evidence")
	}
	for _, enabled := range []bool{false, true} {
		s, area, _, _ := v2Fixture(t, 64)
		if enabled {
			st := clone(s.state)
			addFeatureV2(&st, v2SharedReaderFeature)
			s.preparingShared = true
			err := s.publish(st)
			s.preparingShared = false
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := s.close(); err != nil {
			t.Fatal(err)
		}
		before := journalFiles(t, area.Name())
		// Keep private modes: the unknown durable feature, not filesystem denial,
		// must cause the actual prior binary to refuse the opted-in selection.
		command := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name())
		output, err := command.CombinedOutput()
		want := "OLD_READER_ACCEPTED"
		if enabled {
			want = "OLD_READER_REJECTED"
		}
		if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("enabled=%t: %v %s", enabled, err, output)
		}
	}
}
