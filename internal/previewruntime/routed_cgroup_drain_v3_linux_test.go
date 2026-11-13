//go:build linux

package previewruntime

import "testing"

func TestRoutedCgroupDrainV3RejectsRemainingDescendants(t *testing.T) {
	for _, raw := range []string{"", "41\n42\n", "42\n41\n", "41\n41\n", "42\n", "041\n", "41\ninvalid\n", "0\n"} {
		if routedCgroupOnlySupervisorV3([]byte(raw), 41) {
			t.Fatal("unproven descendant drainage accepted")
		}
	}
	if !routedCgroupOnlySupervisorV3([]byte("41\n"), 41) {
		t.Fatal("single supervisor rejected")
	}
}
