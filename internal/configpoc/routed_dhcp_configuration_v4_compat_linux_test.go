//go:build linux

package configpoc

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// The historical executable includes only a test adapter to its original
// openSharedStoreV2. A private-profile openV2 refusal is not marker evidence.
func TestRoutedDHCPConfigurationV4OldReaderMarker(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply the actual historical shared-reader binary; skip is not compatibility evidence")
	}
	w, authority := dhcpStoreFixtureV3(t)
	work, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	authority.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	s := w.c.store
	area, budget, access, reserves := s.root, s.budget, *s.access, s.reserves
	run := func(want string) {
		t.Helper()
		before := journalFiles(t, area.Name())
		output, err := exec.Command(*reclaimOldReader, "-test.run=^TestDHCPConfigurationPriorReader$", "-prior-dhcp-configuration-area="+area.Name()).CombinedOutput()
		if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("historical shared reader: %v %s", err, output)
		}
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	run("OLD_READER_ACCEPTED")
	s, err = openSharedStoreV2(area, budget, access)
	if err != nil {
		t.Fatal(err)
	}
	s.reserves = reserves
	state := clone(s.state)
	addFeatureV2(&state, v4RoutedDHCPConfigurationFeature)
	// The marker alone is deliberately sufficient: old readers must refuse it
	// after optional transition/continuation payloads are no longer selected.
	if err = s.publish(state); err != nil {
		t.Fatal(err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	run("OLD_READER_REJECTED")
	s, err = openSharedStoreV2(area, budget, access)
	if err != nil {
		t.Fatal("modern reader rejected prepared marker", err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
}
