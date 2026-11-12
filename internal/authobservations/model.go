// Package authobservations stores explicitly selected anonymous login observations.
// It does not own protected audit or enable a runtime migration.
package authobservations

import (
	"errors"
	"net/netip"
	"time"
)

const (
	Feature                 = "anonymous_auth_observations.v1"
	MaximumBytes     uint64 = 4 << 20
	MaximumAge              = 24 * time.Hour
	maximumIntervals        = 1440
	maximumPeers            = 512
	maximumSnapshot         = 512 << 10
)

var (
	ErrInvalid     = errors.New("ANDEIVA_OBSERVATIONS_INVALID")
	ErrUnavailable = errors.New("ANDEIVA_OBSERVATIONS_UNAVAILABLE")
	ErrLimited     = errors.New("ANDEIVA_OBSERVATIONS_LIMITED")
)

// AreaIdentity is supplied by descriptor metadata, never an external request.
type AreaIdentity struct{ Device, Inode uint64 }

// Selection binds this policy to a separately enforced runtime selection.
// Snapshot hashes attest byte-identical protected source and backup inventories.
// This module never rewrites, removes or exports those protected files.
type Selection struct {
	Version   int          `json:"version"`
	Feature   string       `json:"required_feature"`
	ID        string       `json:"id"`
	Runtime   string       `json:"runtime_selection"`
	Protected string       `json:"protected_snapshot"`
	Backup    string       `json:"backup_snapshot"`
	Area      AreaIdentity `json:"area"`
}

// AdmissionGuard is implemented only by trusted runtime selection assembly.
// Selection must verify quiescence, unchanged source/backup and exclusion of old
// writers before selection, and the exact active binding on reopen/admission.
// Capacity verifies isolation from protected audit/recovery allocations. Neither
// directory separation nor fstatfs alone establishes that isolation. There is no
// permissive default provider and no deployed runtime provider in this package.
type AdmissionGuard interface {
	Selection(Selection) error
	Capacity(AreaIdentity, uint64, uint64) error
}

type PeerCount struct {
	Peer  string `json:"peer"`
	Count uint64 `json:"count"`
}
type Interval struct {
	Minute   time.Time   `json:"minute"`
	Created  time.Time   `json:"created"`
	Total    uint64      `json:"total"`
	Overflow uint64      `json:"overflow"`
	Peers    []PeerCount `json:"peers"`
}

type Counters struct {
	Expired         uint64 `json:"expired"`
	CapacityEvicted uint64 `json:"capacity_evicted"`
	Unattributed    uint64 `json:"unattributed"`
	ClockRejected   uint64 `json:"clock_rejected"`
	Saturated       bool   `json:"saturated"`
}

// Report is a lower-bound observation, not an exact post-crash event ledger.
// PersistedThrough describes the last completed snapshot publication. The gap
// after it can include lost observations; UnknownGap is never an invented count.
type Report struct {
	Version          int        `json:"version"`
	Intervals        []Interval `json:"intervals"`
	Counters         Counters   `json:"counters"`
	PersistedThrough time.Time  `json:"persisted_through"`
	UnknownGap       bool       `json:"unknown_gap"`
	Degraded         bool       `json:"degraded"`
	Pending          bool       `json:"pending"`
	AllocatedBytes   uint64     `json:"allocated_bytes"`
	AllocatedKnown   bool       `json:"allocated_known"`
	MemoryOnly       bool       `json:"memory_only"`
}

type snapshot struct {
	Version    int        `json:"version"`
	Policy     string     `json:"policy"`
	Generation uint64     `json:"generation"`
	At         time.Time  `json:"at"`
	Intervals  []Interval `json:"intervals"`
	Counters   Counters   `json:"counters"`
}

func validPeer(peer netip.Addr) bool {
	return peer.IsValid() && peer.Zone() == "" && !peer.IsUnspecified() && !peer.IsMulticast()
}

func increment(value *uint64, add uint64, counters *Counters) {
	if ^uint64(0)-*value < add {
		*value = ^uint64(0)
		counters.Saturated = true
	} else {
		*value += add
	}
}
