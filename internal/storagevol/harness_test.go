package storagevol

import (
	"strings"
	"testing"
)

func harnessFixture() Manifest {
	plan := LabPlan()
	value := Manifest{Format: Format, State: plan.State, ID: strings.Repeat("a", 32), TotalBytes: plan.TotalBytes}
	for _, p := range plan.Volumes {
		value.Volumes = append(value.Volumes, Volume{VolumePlan: p, AllocatedBytes: p.Bytes, Filesystem: "ext4", BlockSize: 4096, UUID: strings.Repeat("b", 32), SHA256: strings.Repeat("c", 64)})
	}
	value.Hash = hashManifest(value)
	return value
}
func TestHarnessPlanCanonicalFixedFields(t *testing.T) {
	value := harnessFixture()
	text, err := EncodeHarnessPlan(value)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 5 || lines[0] != "ANDEIVA_STORAGE_PLAN_V1\t"+value.ID+"\t"+value.Hash {
		t.Fatal("header")
	}
	for i, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 6 || fields[0] != value.Volumes[i].Domain || fields[1] != BaseDirectory+"/volumes-"+value.ID+"/"+value.Volumes[i].File {
			t.Fatal("fields", line)
		}
	}
}
func TestHarnessPlanRejectsInjectionAndChangedManifest(t *testing.T) {
	for _, change := range []func(*Manifest){func(v *Manifest) { v.ID = "../bad" }, func(v *Manifest) { v.Volumes[0].File = "/dev/sda" }, func(v *Manifest) { v.Volumes[0].Domain = "config\nextra" }, func(v *Manifest) { v.Volumes[0].SHA256 = strings.Repeat("z", 64) }, func(v *Manifest) { v.Volumes[0].UUID = "$(id)" }, func(v *Manifest) { v.Volumes[0].Bytes++ }, func(v *Manifest) { v.Volumes[0].AllocatedBytes = 0 }} {
		value := harnessFixture()
		change(&value)
		value.Hash = hashManifest(value)
		if text, err := EncodeHarnessPlan(value); err == nil || text != "" {
			t.Fatal("invalid plan accepted")
		}
	}
	value := harnessFixture()
	value.Hash = strings.Repeat("0", 64)
	if _, err := EncodeHarnessPlan(value); err == nil {
		t.Fatal("changed hash accepted")
	}
}
