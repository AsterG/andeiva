package recoveryreserve

import (
	"bytes"
	"encoding/json"
	"reflect"
)

func (p *PoolV2) writePair(index int, r recordV2, phase string) error {
	if !p.validRecord(r, index) {
		return ErrInvalid
	}
	first := int(r.Sequence % 2)
	f := p.slots[index].file
	for step, bank := range []int{first, 1 - first} {
		if writeHeaderV2(f, int64(bank)*bankSizeV2(p.manifest.Capacity), r) != nil {
			p.blocked = true
			return ErrUnavailable
		}
		point := "_first_written"
		if step == 1 {
			point = "_second_written"
		}
		if p.point(phase+point) != nil {
			p.blocked = true
			return ErrUnavailable
		}
		if f.Sync() != nil {
			p.blocked = true
			return ErrUnavailable
		}
		point = "_first_synced"
		if step == 1 {
			point = "_second_synced"
		}
		if p.point(phase+point) != nil {
			p.blocked = true
			return ErrUnavailable
		}
		actual, _, err := p.readBank(index, bank)
		if err != nil || !reflect.DeepEqual(actual, r) || p.identity() != nil {
			p.blocked = true
			return ErrUnavailable
		}
	}
	actual, err := p.inspect(index)
	if err != nil || !actual.identical || !reflect.DeepEqual(actual.record, r) {
		p.blocked = true
		return ErrUnavailable
	}
	return nil
}

func (p *PoolV2) Claim(owner string) (SlotClaimV2, error) {
	return p.claim(owner, "")
}

// ClaimClass enforces the approved 18-slot profile without caller-provided
// ranges: 8 ordinary, 8 closing, 2 autonomous. It never borrows another class.
func (p *PoolV2) ClaimClass(owner string, class ClassV2) (SlotClaimV2, error) {
	if class != OrdinaryV2 && class != ClosingV2 && class != SystemV2 {
		return SlotClaimV2{}, ErrInvalid
	}
	return p.claim(owner, class)
}

func (p *PoolV2) claim(owner string, class ClassV2) (SlotClaimV2, error) {
	if p == nil || owner == "" || !validOwner(owner) {
		return SlotClaimV2{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return SlotClaimV2{}, ErrUnavailable
	}
	low, high := 0, len(p.slots)
	if class != "" {
		if len(p.slots) != 18 {
			return SlotClaimV2{}, ErrInvalid
		}
		switch class {
		case OrdinaryV2:
			low, high = 0, 8
		case ClosingV2:
			low, high = 8, 16
		case SystemV2:
			low, high = 16, 18
		}
	}
	readyIndex := -1
	var ready recordV2
	for i := range p.slots {
		observed, err := p.inspect(i)
		if err != nil {
			return SlotClaimV2{}, ErrUnavailable
		}
		r := observed.record
		if r.Owner == owner {
			if i < low || i >= high {
				return SlotClaimV2{}, ErrConflict
			}
			if r.State == "written" || (r.State == "claimed" && observed.identical) {
				if p.slots[i].file.Sync() != nil || p.identity() != nil {
					p.blocked = true
					return SlotClaimV2{}, ErrUnavailable
				}
				return p.claimRecord(r), nil
			}
			return SlotClaimV2{}, ErrUnavailable
		}
		if i >= low && i < high && r.State == "ready" && observed.identical && readyIndex < 0 {
			readyIndex = i
			ready = r
		}
	}
	if readyIndex < 0 {
		return SlotClaimV2{}, ErrFull
	}
	if ready.Sequence == ^uint64(0) {
		return SlotClaimV2{}, ErrFull
	}
	r := recordV2{Format: formatV2, Pool: p.manifest.ID, Slot: readyIndex, Role: p.manifest.Role, State: "claimed", Epoch: ready.Epoch, Sequence: ready.Sequence + 1, ClaimSequence: ready.Sequence + 1, Owner: owner, Digest: digest(nil)}
	if err := p.writePair(readyIndex, r, "claim"); err != nil {
		return SlotClaimV2{}, err
	}
	return p.claimRecord(r), nil
}

// WriteOnce never changes a selected payload. An exact idempotent retry may
// re-observe and sync the same complete record; another scope or bytes conflict.
func (p *PoolV2) WriteOnce(claim SlotClaimV2, payload []byte, scope ScopeV2) (BindingV2, error) {
	if p == nil || !validClaimV2(claim) || len(payload) > claim.Capacity {
		return BindingV2{}, ErrInvalid
	}
	scopeHash, err := scope.Hash()
	if err != nil || scope.Bundle != claim.Owner {
		return BindingV2{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return BindingV2{}, ErrUnavailable
	}
	if !p.claimMatches(claim, claim.Slot) {
		return BindingV2{}, ErrConflict
	}
	observed, err := p.inspect(claim.Slot)
	if err != nil {
		return BindingV2{}, ErrUnavailable
	}
	r := observed.record
	if p.claimRecord(r) != claim {
		return BindingV2{}, ErrConflict
	}
	if r.State == "written" {
		if r.ScopeHash != scopeHash || r.Digest != digest(payload) || !bytes.Equal(payload, observed.data) {
			return BindingV2{}, ErrConflict
		}
		if p.slots[claim.Slot].file.Sync() != nil || p.identity() != nil {
			p.blocked = true
			return BindingV2{}, ErrUnavailable
		}
		return p.bindingRecord(r), nil
	}
	if r.State != "claimed" || !observed.identical {
		return BindingV2{}, ErrUnavailable
	}
	if r.Sequence == ^uint64(0) {
		return BindingV2{}, ErrFull
	}
	r.State = "written"
	r.Sequence++
	r.Length = len(payload)
	r.Digest = digest(payload)
	r.ScopeHash = scopeHash
	f := p.slots[claim.Slot].file
	offset := int64(r.Sequence%2) * bankSizeV2(p.manifest.Capacity)
	if len(payload) > 0 {
		n, err := f.WriteAt(payload, offset+headerV2)
		if err != nil || n != len(payload) {
			p.blocked = true
			return BindingV2{}, ErrUnavailable
		}
	}
	if p.point("write_payload_written") != nil || f.Sync() != nil || p.point("write_payload_synced") != nil {
		p.blocked = true
		return BindingV2{}, ErrUnavailable
	}
	if writeHeaderV2(f, offset, r) != nil || p.point("write_header_written") != nil || f.Sync() != nil || p.point("write_header_synced") != nil {
		p.blocked = true
		return BindingV2{}, ErrUnavailable
	}
	actual, err := p.inspect(claim.Slot)
	if err != nil || !reflect.DeepEqual(actual.record, r) || !bytes.Equal(actual.data, payload) || p.identity() != nil {
		p.blocked = true
		return BindingV2{}, ErrUnavailable
	}
	return p.bindingRecord(r), nil
}

func (p *PoolV2) ReadBound(binding BindingV2) ([]byte, error) {
	if p == nil || !validBindingV2(binding) {
		return nil, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.identity() != nil {
		return nil, ErrUnavailable
	}
	if !p.claimMatches(binding.Claim, binding.Claim.Slot) {
		return nil, ErrConflict
	}
	observed, err := p.inspect(binding.Claim.Slot)
	if err != nil || observed.record.State != "written" || p.bindingRecord(observed.record) != binding {
		return nil, ErrUnavailable
	}
	if p.slots[binding.Claim.Slot].file.Sync() != nil || p.identity() != nil {
		p.blocked = true
		return nil, ErrUnavailable
	}
	return append([]byte(nil), observed.data...), nil
}

// InspectClaimed returns evidence, not selected configuration or finality.
// Empty, torn, retired and foreign claims never produce a fallback candidate.
func (p *PoolV2) InspectClaimed(claim SlotClaimV2) (CandidateV2, error) {
	if p == nil || !validClaimV2(claim) {
		return CandidateV2{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.identity() != nil {
		return CandidateV2{}, ErrUnavailable
	}
	if !p.claimMatches(claim, claim.Slot) {
		return CandidateV2{}, ErrConflict
	}
	observed, err := p.inspect(claim.Slot)
	if err != nil {
		return CandidateV2{}, ErrUnavailable
	}
	if observed.record.State != "written" || p.claimRecord(observed.record) != claim {
		return CandidateV2{}, ErrConflict
	}
	if p.slots[claim.Slot].file.Sync() != nil || p.identity() != nil {
		p.blocked = true
		return CandidateV2{}, ErrUnavailable
	}
	return CandidateV2{Binding: p.bindingRecord(observed.record), Bytes: append([]byte(nil), observed.data...)}, nil
}

func proofDigestV2(expected ExpectedV2, proof RetirementProofV2) (string, error) {
	if !validExpectedV2(expected) || proof.Scope.Validate() != nil || proof.Scope.Bundle != expected.Claim.Owner || !digestV2(proof.Archive) || !digestV2(proof.FinalAudit) {
		return "", ErrInvalid
	}
	scopeHash, err := proof.Scope.Hash()
	if err != nil {
		return "", ErrInvalid
	}
	if expected.Written != nil && expected.Written.ScopeHash != scopeHash {
		return "", ErrConflict
	}
	work := proof.Scope.Operation
	if work == "" {
		work = proof.Scope.Recovery
	}
	if proof.FinalWork != work {
		return "", ErrInvalid
	}
	if proof.Scope.Lease != "" {
		if proof.Finality != "lease_resolved" || !digestV2(proof.LeaseResolution) {
			return "", ErrInvalid
		}
	} else if proof.LeaseResolution != "" || (proof.Scope.Kind == "operation" && proof.Finality != "operation_final") || (proof.Scope.Kind != "operation" && proof.Finality != "recovery_final") {
		return "", ErrInvalid
	}
	for _, view := range []SelectionProofV2{proof.Current, proof.Previous} {
		if !digestV2(view.Selection) || !digestV2(view.State) || !digestV2(view.ArchiveRoot) || view.Sequence == 0 || view.Lineage != proof.Scope.Lineage {
			return "", ErrInvalid
		}
	}
	if proof.Previous.Sequence == ^uint64(0) || proof.Current.Sequence != proof.Previous.Sequence+1 || proof.Current.Selection == proof.Previous.Selection {
		return "", ErrInvalid
	}
	proof.Scope.Deadline = proof.Scope.Deadline.UTC()
	data, err := json.Marshal(proof)
	if err != nil {
		return "", ErrInvalid
	}
	return digest(data), nil
}

// RetireCAS consumes a structured proof produced by the canonical coordinator.
// It cannot itself verify that archive/selector hashes are selected: that check
// belongs under the caller's store lock. It never releases by age or a boolean.
func (p *PoolV2) RetireCAS(expected ExpectedV2, proof RetirementProofV2) error {
	if p == nil {
		return ErrInvalid
	}
	if expected.Written != nil {
		b := *expected.Written
		expected.Written = &b
	}
	proofHash, err := proofDigestV2(expected, proof)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return ErrUnavailable
	}
	if !p.claimMatches(expected.Claim, expected.Claim.Slot) {
		return ErrConflict
	}
	seq := expectedSequenceV2(expected)
	if seq > ^uint64(0)-3 || expected.Claim.Epoch == ^uint64(0) {
		return ErrFull
	}
	index := expected.Claim.Slot
	observed, err := p.inspect(index)
	if err != nil {
		return ErrUnavailable
	}
	note := &retirementV2{Expected: expected, Proof: proofHash}
	if observed.record.Retirement != nil {
		if !reflect.DeepEqual(observed.record.Retirement, note) {
			return ErrConflict
		}
		if observed.record.State == "ready" && observed.identical {
			if p.slots[index].file.Sync() != nil || p.identity() != nil {
				p.blocked = true
				return ErrUnavailable
			}
			return nil
		}
	} else {
		if expected.Written == nil {
			if observed.record.State != "claimed" || !observed.identical || p.claimRecord(observed.record) != expected.Claim {
				return ErrConflict
			}
		} else if observed.record.State != "written" || p.bindingRecord(observed.record) != *expected.Written {
			return ErrConflict
		}
	}
	r := recordV2{Format: formatV2, Pool: p.manifest.ID, Slot: index, Role: p.manifest.Role, State: "retired_held", Epoch: expected.Claim.Epoch, Sequence: seq + 1, ClaimSequence: expected.Claim.ClaimSequence, Owner: expected.Claim.Owner, Digest: digest(nil), Retirement: note}
	stages := []recordV2{r}
	r.State = "free_prepared"
	r.Epoch++
	r.Sequence++
	r.Owner = ""
	r.ClaimSequence = 0
	r.Length = 0
	r.Digest = digest(nil)
	r.ScopeHash = ""
	stages = append(stages, r)
	r.State = "ready"
	r.Sequence++
	stages = append(stages, r)
	for _, stage := range stages {
		if observed.record.Sequence > stage.Sequence {
			continue
		}
		if observed.record.Sequence == stage.Sequence && !reflect.DeepEqual(observed.record, stage) {
			return ErrConflict
		}
		if err = p.writePair(index, stage, "retire_"+stage.State); err != nil {
			return err
		}
		observed, err = p.inspect(index)
		if err != nil {
			p.blocked = true
			return ErrUnavailable
		}
	}
	return nil
}
