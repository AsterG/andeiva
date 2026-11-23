//go:build linux

package previewruntime

import (
	"strings"
	"testing"
)

func TestActivationUnitRequiresDurableMaskAndDrain(t *testing.T) {
	drained := "LoadState=masked\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n"
	for _, tc := range []struct {
		name   string
		status string
		expect bool
	}{
		{"masked", drained, true},
		{"loaded", strings.Replace(drained, "masked", "loaded", 1), false},
		{"active", strings.Replace(drained, "inactive", "active", 1), false},
		{"cgroup", strings.Replace(drained, "ControlGroup=", "ControlGroup=/system.slice/andeiva-preview-grouped.service", 1), false},
		{"main process", strings.Replace(drained, "MainPID=0", "MainPID=137", 1), false},
		{"control process", strings.Replace(drained, "ControlPID=0", "ControlPID=138", 1), false},
		{"duplicate", drained + "ActiveState=active\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := activationUnitDrainedV1(tc.status, true); got != tc.expect {
				t.Fatalf("drained = %t, want %t", got, tc.expect)
			}
		})
	}
}
