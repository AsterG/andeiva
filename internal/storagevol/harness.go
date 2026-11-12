package storagevol

import (
	"fmt"
	"strings"
)

// EncodeHarnessPlan emits only fixed profile paths and canonical verified fields.
// Callers must obtain the manifest through Inspect immediately before use.
func EncodeHarnessPlan(value Manifest) (string, error) {
	plan := LabPlan()
	if !validID(value.ID) || value.Format != Format || value.State != plan.State || value.TotalBytes != plan.TotalBytes || len(value.Volumes) != len(plan.Volumes) || value.Hash != hashManifest(value) {
		return "", ErrInvalid
	}
	var result strings.Builder
	fmt.Fprintf(&result, "ANDEIVA_STORAGE_PLAN_V1\t%s\t%s\n", value.ID, value.Hash)
	for i, volume := range value.Volumes {
		if volume.VolumePlan != plan.Volumes[i] || volume.Filesystem != "ext4" || volume.BlockSize != 4096 || !validID(volume.UUID) || volume.UUID == strings.Repeat("0", 32) || len(volume.SHA256) != 64 || volume.AllocatedBytes < volume.Bytes || volume.AllocatedBytes > volume.Bytes+mib {
			return "", ErrInvalid
		}
		for _, digit := range volume.SHA256 {
			if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
				return "", ErrInvalid
			}
		}
		fmt.Fprintf(&result, "%s\t%s/volumes-%s/%s\t%s\t%s\t%d\t%d\n", volume.Domain, BaseDirectory, value.ID, volume.File, volume.SHA256, volume.UUID, volume.Bytes, volume.Inodes)
	}
	return result.String(), nil
}
