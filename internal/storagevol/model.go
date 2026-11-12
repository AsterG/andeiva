// Package storagevol prepares inactive, bounded filesystem images for laboratory tests.
// It does not mount images, configure the appliance or provide a management API.
package storagevol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	BaseDirectory    = "/var/lib/andeiva-storage-lab"
	Format           = "andeiva-storage-lab-v1"
	manifestName     = "manifest.json"
	pendingName      = "manifest.pending"
	maxManifestBytes = 16384
	mib              = uint64(1024 * 1024)
)

var (
	ErrPlatform   = errors.New("ANDEIVA_STORAGE_VOLUME_PLATFORM")
	ErrInvalid    = errors.New("ANDEIVA_STORAGE_VOLUME_INVALID")
	ErrUnsafe     = errors.New("ANDEIVA_STORAGE_VOLUME_UNSAFE")
	ErrExists     = errors.New("ANDEIVA_STORAGE_VOLUME_EXISTS")
	ErrStorage    = errors.New("ANDEIVA_STORAGE_VOLUME_IO")
	ErrIncomplete = errors.New("ANDEIVA_STORAGE_VOLUME_INCOMPLETE")
	ErrUncertain  = errors.New("ANDEIVA_STORAGE_VOLUME_UNCERTAIN")
	ErrLocked     = errors.New("ANDEIVA_STORAGE_VOLUME_LOCKED")
	ErrCapacity   = errors.New("ANDEIVA_STORAGE_VOLUME_CAPACITY")
	ErrFormatter  = errors.New("ANDEIVA_STORAGE_VOLUME_FORMATTER")
)

type VolumePlan struct {
	Domain string `json:"domain"`
	File   string `json:"file"`
	Bytes  uint64 `json:"bytes,string"`
	Inodes uint32 `json:"inodes"`
}

type Plan struct {
	Format     string       `json:"format"`
	State      string       `json:"state"`
	TotalBytes uint64       `json:"total_bytes,string"`
	Volumes    []VolumePlan `json:"volumes"`
}

type Volume struct {
	VolumePlan
	AllocatedBytes uint64 `json:"allocated_bytes,string"`
	Filesystem     string `json:"filesystem"`
	BlockSize      uint32 `json:"block_size"`
	UUID           string `json:"uuid"`
	SHA256         string `json:"sha256"`
}

type Manifest struct {
	Format     string   `json:"format"`
	State      string   `json:"state"`
	ID         string   `json:"id"`
	TotalBytes uint64   `json:"total_bytes,string"`
	Volumes    []Volume `json:"volumes"`
	Hash       string   `json:"hash"`
}

// LabPlan is a finite test profile, not a supported appliance sizing default.
func LabPlan() Plan {
	return Plan{Format: Format, State: "inactive_preparation", TotalBytes: 384 * mib, Volumes: []VolumePlan{
		{"config", "config.img", 128 * mib, 8192},
		{"audit", "audit.img", 128 * mib, 4096},
		{"observations", "observations.img", 64 * mib, 1024},
		{"recovery", "recovery.img", 64 * mib, 2048},
	}}
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

func hashManifest(value Manifest) string {
	value.Hash = ""
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validPlans(plans []VolumePlan) bool {
	standard := LabPlan().Volumes
	if len(plans) != len(standard) {
		return false
	}
	var total uint64
	for i, p := range plans {
		if p.Domain != standard[i].Domain || p.File != standard[i].File || p.Bytes < 4*mib || p.Bytes > 128*mib || p.Bytes%4096 != 0 || p.Inodes < 128 || p.Inodes > 16384 {
			return false
		}
		total += p.Bytes
	}
	return total <= 384*mib
}
