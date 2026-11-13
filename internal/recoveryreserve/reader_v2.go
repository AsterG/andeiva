package recoveryreserve

import (
	"context"
	"io"
	"os"
	"reflect"
)

// ReadOnlyPoolV2 owns read-only descriptors and borrows area. It never takes a
// flock, syncs, repairs, publishes, or grants authority to apply configuration.
// The supervisor must fence writer incarnations; the coordinator must hold its
// publication barrier across verification and the requested helper effect.
type ReadOnlyPoolV2 struct{ pool *PoolV2 }

type observedBanksV2 struct {
	records  [2]recordV2
	data     [2][]byte
	selected inspectionV2
}

// PoolSnapshotV2 is process-local evidence, not a wire DTO or capability. Its
// bytes are immutable to callers. A snapshot alone does not prove selection,
// finality, or that the files have remained unchanged since observation.
type PoolSnapshotV2 struct {
	source  *ReadOnlyPoolV2
	profile ProfileV2
	slots   []observedBanksV2
}

func (PoolSnapshotV2) String() string   { return "reserve snapshot (opaque)" }
func (PoolSnapshotV2) GoString() string { return "reserve snapshot (opaque)" }

// SlotObservationV2 describes actual verified bank state. Retired and ready
// slots have no live claim/binding. No payload is exposed in this inventory.
type SlotObservationV2 struct {
	State           string
	Epoch, Sequence uint64
	BanksEqual      bool
	Claim           *SlotClaimV2
	Binding         *BindingV2
}

func OpenReadOnlyV2(area *os.Root, access ReaderAccessV2, expected ProfileV2) (*ReadOnlyPoolV2, error) {
	if area == nil || !access.valid() || !accessReaderV2(access) || !poolIDV2(expected.ID) || !validRoleV2(expected.Role) || !validProfile(expected.Slots, expected.Capacity) {
		return nil, ErrInvalid
	}
	p, err := openAccessV2(area, &access, true)
	if err != nil {
		return nil, err
	}
	if profileOfV2(p.manifest) != expected {
		if p.Close() != nil {
			return nil, ErrUnavailable
		}
		return nil, ErrConflict
	}
	return &ReadOnlyPoolV2{pool: p}, nil
}

func profileOfV2(m manifestV2) ProfileV2 {
	return ProfileV2{ID: m.ID, Role: m.Role, Slots: m.Slots, Capacity: m.Capacity}
}

func (r *ReadOnlyPoolV2) Close() error {
	if r == nil || r.pool == nil {
		return nil
	}
	return r.pool.Close()
}

// capture is called with the reader's mutex, never the writer's mutex/flock.
// Both banks are retained: a change to the older bank must invalidate evidence
// even when the winning record would be identical.
func (r *ReadOnlyPoolV2) capture(ctx context.Context) (PoolSnapshotV2, error) {
	p := r.pool
	if ctx.Err() != nil || p.closed || p.identity() != nil {
		return PoolSnapshotV2{}, ErrUnavailable
	}
	size := p.lockInfo.Size()
	if size < 1 || size > 4096 {
		return PoolSnapshotV2{}, ErrUnavailable
	}
	data := make([]byte, size+1)
	n, err := p.lock.ReadAt(data, 0)
	var manifest manifestV2
	if err != io.EOF || int64(n) != size || !strict(data[:n], &manifest) || manifest != p.manifest {
		return PoolSnapshotV2{}, ErrUnavailable
	}
	out := PoolSnapshotV2{source: r, profile: profileOfV2(manifest), slots: make([]observedBanksV2, len(p.slots))}
	owners := make(map[string]bool, len(p.slots))
	for index := range p.slots {
		if ctx.Err() != nil {
			return PoolSnapshotV2{}, ErrUnavailable
		}
		s := &out.slots[index]
		for bank := 0; bank < 2; bank++ {
			s.records[bank], s.data[bank], err = p.readBank(index, bank)
			if err != nil {
				return PoolSnapshotV2{}, err
			}
		}
		s.selected, err = p.resolveBanksV2(s.records[0], s.data[0], s.records[1], s.data[1])
		if err != nil {
			return PoolSnapshotV2{}, err
		}
		owner := s.selected.record.Owner
		if owner != "" {
			if owners[owner] {
				return PoolSnapshotV2{}, ErrUnavailable
			}
			owners[owner] = true
		}
	}
	if ctx.Err() != nil || p.identity() != nil {
		return PoolSnapshotV2{}, ErrUnavailable
	}
	return out, nil
}

// Snapshot performs two bounded captures. A concurrent change is an error, not
// a retry or permission to choose whichever bank was most convenient. This is
// an observation under the caller's barrier, not an atomic disk/kernel CAS.
func (r *ReadOnlyPoolV2) Snapshot(ctx context.Context) (PoolSnapshotV2, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return PoolSnapshotV2{}, ErrInvalid
	}
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	first, err := r.capture(ctx)
	if err != nil {
		return PoolSnapshotV2{}, err
	}
	second, err := r.capture(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return PoolSnapshotV2{}, ErrUnavailable
	}
	return second, nil
}

func (r *ReadOnlyPoolV2) Revalidate(ctx context.Context, previous PoolSnapshotV2) error {
	if r == nil || previous.source != r || previous.slots == nil {
		return ErrInvalid
	}
	next, err := r.Snapshot(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(previous, next) {
		return ErrConflict
	}
	return nil
}

func (s PoolSnapshotV2) Profile() (ProfileV2, error) {
	if s.source == nil || s.slots == nil {
		return ProfileV2{}, ErrInvalid
	}
	return s.profile, nil
}

func (s PoolSnapshotV2) Slots() []SlotObservationV2 {
	if s.source == nil {
		return nil
	}
	out := make([]SlotObservationV2, len(s.slots))
	p := &PoolV2{manifest: manifestV2{ID: s.profile.ID, Role: s.profile.Role, Capacity: s.profile.Capacity}}
	for i, slot := range s.slots {
		r := slot.selected.record
		o := SlotObservationV2{State: r.State, Epoch: r.Epoch, Sequence: r.Sequence, BanksEqual: slot.selected.identical}
		if r.State == "claimed" || r.State == "written" {
			c := p.claimRecord(r)
			o.Claim = &c
		}
		if r.State == "written" {
			b := p.bindingRecord(r)
			o.Binding = &b
		}
		out[i] = o
	}
	return out
}

func (s PoolSnapshotV2) InspectClaimed(claim SlotClaimV2) (CandidateV2, error) {
	if s.source == nil || !validClaimV2(claim) || claim.Pool != s.profile.ID || claim.Role != s.profile.Role || claim.Capacity != s.profile.Capacity || claim.Slot >= len(s.slots) {
		return CandidateV2{}, ErrInvalid
	}
	p := &PoolV2{manifest: manifestV2{ID: s.profile.ID, Role: s.profile.Role, Capacity: s.profile.Capacity}}
	actual := s.slots[claim.Slot].selected
	if actual.record.State != "written" || p.claimRecord(actual.record) != claim {
		return CandidateV2{}, ErrConflict
	}
	return CandidateV2{Binding: p.bindingRecord(actual.record), Bytes: append([]byte(nil), actual.data...)}, nil
}

func (s PoolSnapshotV2) ReadBound(binding BindingV2) ([]byte, error) {
	if !validBindingV2(binding) {
		return nil, ErrInvalid
	}
	c, err := s.InspectClaimed(binding.Claim)
	if err != nil {
		return nil, err
	}
	if c.Binding != binding {
		return nil, ErrConflict
	}
	return c.Bytes, nil
}
