package recoveryreserve

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"
)

type manifestV2 struct {
	Format   string `json:"format"`
	ID       string `json:"id"`
	Slots    int    `json:"slots"`
	Capacity int    `json:"capacity"`
	Role     RoleV2 `json:"role"`
	Header   int    `json:"header"`
}

type retirementV2 struct {
	Expected ExpectedV2 `json:"expected"`
	Proof    string     `json:"proof"`
}

type recordV2 struct {
	Format        string        `json:"format"`
	Pool          string        `json:"pool"`
	Slot          int           `json:"slot"`
	Role          RoleV2        `json:"role"`
	State         string        `json:"state"`
	Epoch         uint64        `json:"epoch,string"`
	Sequence      uint64        `json:"sequence,string"`
	ClaimSequence uint64        `json:"claim_sequence,string"`
	Owner         string        `json:"owner"`
	Length        int           `json:"length"`
	Digest        string        `json:"digest"`
	ScopeHash     string        `json:"scope_hash,omitempty"`
	Retirement    *retirementV2 `json:"retirement,omitempty"`
}

type diskHeaderV2 struct {
	Record   recordV2 `json:"record"`
	Checksum string   `json:"checksum"`
}

type slotV2 struct {
	file *os.File
	info os.FileInfo
}
type inspectionV2 struct {
	record    recordV2
	data      []byte
	identical bool
}

// PoolV2 owns its file handles and exclusive manifest lock, but borrows root.
// Canonical selection/authorization remain the caller's responsibility.
type PoolV2 struct {
	mu              sync.Mutex
	root            *os.Root
	rootInfo        os.FileInfo
	lock            *os.File
	lockInfo        os.FileInfo
	manifest        manifestV2
	slots           []slotV2
	closed, blocked bool
	hook            func(string) error
	access          *ReaderAccessV2
	readOnly        bool
}

func digestV2(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && hex.EncodeToString(data) == value
}
func poolIDV2(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 16 && hex.EncodeToString(data) == value
}
func bootV2(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	text := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	return poolIDV2(text) && text != "00000000000000000000000000000000"
}

func validManifestV2(m manifestV2) bool {
	return m.Format == formatV2 && poolIDV2(m.ID) && validProfile(m.Slots, m.Capacity) && validRoleV2(m.Role) && m.Header == headerV2
}
func bankSizeV2(capacity int) int64 { return int64(headerV2 + capacity) }

// PrepareV2 only accepts an empty private directory. Failure preserves partial
// preparation for inspection; it never removes or adopts another layout.
func PrepareV2(area *os.Root, slots, capacity int, role RoleV2) (*PoolV2, error) {
	return prepareV2(area, slots, capacity, role, nil)
}

func prepareV2(area *os.Root, slots, capacity int, role RoleV2, access *ReaderAccessV2) (*PoolV2, error) {
	if area == nil || !validProfile(slots, capacity) || !validRoleV2(role) {
		return nil, ErrInvalid
	}
	if platform() != nil {
		return nil, ErrUnavailable
	}
	info, err := area.Stat(".")
	if err != nil || !accessDirectoryV2(area, info, access) {
		return nil, ErrUnavailable
	}
	dir, err := area.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	entries, readErr := dir.ReadDir(1)
	closeErr := dir.Close()
	if len(entries) != 0 || readErr != io.EOF || closeErr != nil {
		return nil, ErrUnavailable
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, ErrUnavailable
	}
	m := manifestV2{formatV2, hex.EncodeToString(random[:]), slots, capacity, role, headerV2}
	for index := 0; index < slots; index++ {
		f, e := createAccessFileV2(area, slotName(index), access)
		if e != nil {
			return nil, ErrUnavailable
		}
		e = allocate(f, 2*bankSizeV2(capacity))
		r := recordV2{Format: formatV2, Pool: m.ID, Slot: index, Role: role, State: "ready", Epoch: 1, Sequence: 1, Digest: digest(nil)}
		for bank := 0; bank < 2 && e == nil; bank++ {
			e = writeHeaderV2(f, int64(bank)*bankSizeV2(capacity), r)
		}
		if e == nil {
			e = f.Sync()
		}
		if f.Close() != nil {
			e = ErrUnavailable
		}
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, ErrUnavailable
	}
	f, err := createAccessFileV2(area, "pool.json", access)
	if err != nil {
		return nil, ErrUnavailable
	}
	n, err := f.Write(data)
	if err == nil && n == len(data) {
		err = f.Sync()
	} else {
		err = ErrUnavailable
	}
	if f.Close() != nil {
		err = ErrUnavailable
	}
	if err != nil || syncArea(area) != nil {
		return nil, ErrUnavailable
	}
	return openAccessV2(area, access, false)
}

func OpenV2(area *os.Root) (pool *PoolV2, result error) {
	return openAccessV2(area, nil, false)
}

func openAccessV2(area *os.Root, access *ReaderAccessV2, readOnly bool) (pool *PoolV2, result error) {
	if area == nil {
		return nil, ErrInvalid
	}
	if platform() != nil {
		return nil, ErrUnavailable
	}
	info, err := area.Stat(".")
	if err != nil || !accessDirectoryV2(area, info, access) {
		return nil, ErrUnavailable
	}
	p := &PoolV2{root: area, rootInfo: info, access: access, readOnly: readOnly}
	defer func() {
		if result != nil {
			_ = p.Close()
		}
	}()
	p.lock, err = openAccessFileV2(area, "pool.json", readOnly)
	if err != nil {
		return nil, ErrUnavailable
	}
	p.lockInfo, err = p.lock.Stat()
	if err != nil || !accessFileV2(p.lock, p.lockInfo, info, access) || p.lockInfo.Size() < 1 || p.lockInfo.Size() > 4096 || (!readOnly && lock(p.lock) != nil) {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(p.lock, 4097))
	if err != nil || len(data) > 4096 || !strict(data, &p.manifest) || !validManifestV2(p.manifest) {
		return nil, ErrUnavailable
	}
	dir, err := area.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	entries, readErr := dir.ReadDir(p.manifest.Slots + 2)
	closeErr := dir.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) != p.manifest.Slots+1 {
		return nil, ErrUnavailable
	}
	for _, entry := range entries {
		known := entry.Name() == "pool.json"
		for i := 0; i < p.manifest.Slots; i++ {
			known = known || entry.Name() == slotName(i)
		}
		if !known {
			return nil, ErrUnavailable
		}
	}
	owners := map[string]bool{}
	for index := 0; index < p.manifest.Slots; index++ {
		f, e := openAccessFileV2(area, slotName(index), readOnly)
		if e != nil {
			return nil, ErrUnavailable
		}
		p.slots = append(p.slots, slotV2{file: f})
		s := &p.slots[index]
		s.info, e = f.Stat()
		if e != nil || !accessFileV2(f, s.info, info, access) || s.info.Size() != 2*bankSizeV2(p.manifest.Capacity) || !fullyAllocated(s.info) {
			return nil, ErrUnavailable
		}
		observed, e := p.inspect(index)
		if e != nil {
			return nil, ErrUnavailable
		}
		if observed.record.Owner != "" {
			if owners[observed.record.Owner] {
				return nil, ErrUnavailable
			}
			owners[observed.record.Owner] = true
		}
	}
	if p.identity() != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}

func writeHeaderV2(f *os.File, offset int64, r recordV2) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	data, err := json.Marshal(diskHeaderV2{r, digest(raw)})
	if err != nil || len(data) >= headerV2 {
		return ErrUnavailable
	}
	header := make([]byte, headerV2)
	copy(header, data)
	n, err := f.WriteAt(header, offset)
	if err != nil || n != len(header) {
		return ErrUnavailable
	}
	return nil
}

func validClaimV2(c SlotClaimV2) bool {
	return poolIDV2(c.Pool) && c.Slot >= 0 && c.Slot < 32 && c.Epoch > 0 && c.ClaimSequence >= 2 && c.Owner != "" && validOwner(c.Owner) && validRoleV2(c.Role) && validProfile(1, c.Capacity)
}
func validBindingV2(b BindingV2) bool {
	return validClaimV2(b.Claim) && b.Claim.ClaimSequence != ^uint64(0) && b.Sequence == b.Claim.ClaimSequence+1 && b.Length >= 0 && b.Length <= b.Claim.Capacity && digestV2(b.Digest) && digestV2(b.ScopeHash)
}
func validExpectedV2(e ExpectedV2) bool {
	return validClaimV2(e.Claim) && (e.Written == nil || (validBindingV2(*e.Written) && e.Written.Claim == e.Claim))
}
func expectedSequenceV2(e ExpectedV2) uint64 {
	if e.Written != nil {
		return e.Written.Sequence
	}
	return e.Claim.ClaimSequence
}

func (p *PoolV2) claimRecord(r recordV2) SlotClaimV2 {
	return SlotClaimV2{p.manifest.ID, r.Slot, r.Epoch, r.Owner, r.Role, r.ClaimSequence, p.manifest.Capacity}
}
func (p *PoolV2) bindingRecord(r recordV2) BindingV2 {
	return BindingV2{p.claimRecord(r), r.Sequence, r.Digest, r.Length, r.ScopeHash}
}
func (p *PoolV2) claimMatches(c SlotClaimV2, index int) bool {
	return index >= 0 && index < len(p.slots) && validClaimV2(c) && c.Pool == p.manifest.ID && c.Slot == index && c.Role == p.manifest.Role && c.Capacity == p.manifest.Capacity
}

func (p *PoolV2) validRecord(r recordV2, index int) bool {
	if r.Format != formatV2 || r.Pool != p.manifest.ID || r.Slot != index || r.Role != p.manifest.Role || r.Epoch == 0 || r.Sequence == 0 || r.Length < 0 || r.Length > p.manifest.Capacity || !digestV2(r.Digest) {
		return false
	}
	switch r.State {
	case "claimed":
		return r.Retirement == nil && r.ClaimSequence == r.Sequence && p.claimMatches(p.claimRecord(r), index) && r.Length == 0 && r.Digest == digest(nil) && r.ScopeHash == ""
	case "written":
		return r.Retirement == nil && validBindingV2(p.bindingRecord(r)) && p.claimMatches(p.claimRecord(r), index)
	case "ready":
		if r.Owner != "" || r.ClaimSequence != 0 || r.Length != 0 || r.Digest != digest(nil) || r.ScopeHash != "" {
			return false
		}
		if r.Retirement == nil {
			return r.Epoch == 1 && r.Sequence == 1
		}
	case "retired_held", "free_prepared":
	default:
		return false
	}
	note := r.Retirement
	if note == nil || !validExpectedV2(note.Expected) || !p.claimMatches(note.Expected.Claim, index) || !digestV2(note.Proof) {
		return false
	}
	e := note.Expected
	seq := expectedSequenceV2(e)
	if seq > ^uint64(0)-3 || e.Claim.Epoch == ^uint64(0) {
		return false
	}
	if r.State == "retired_held" {
		if p.claimRecord(r) != e.Claim || r.Sequence != seq+1 {
			return false
		}
		return r.Length == 0 && r.Digest == digest(nil) && r.ScopeHash == ""
	}
	step := uint64(2)
	if r.State == "ready" {
		step = 3
	}
	return r.Epoch == e.Claim.Epoch+1 && r.Sequence == seq+step && r.Owner == "" && r.ClaimSequence == 0 && r.Length == 0 && r.Digest == digest(nil) && r.ScopeHash == ""
}

func (p *PoolV2) readBank(index, bank int) (recordV2, []byte, error) {
	f := p.slots[index].file
	offset := int64(bank) * bankSizeV2(p.manifest.Capacity)
	header := make([]byte, headerV2)
	if _, err := f.ReadAt(header, offset); err != nil {
		return recordV2{}, nil, ErrUnavailable
	}
	var h diskHeaderV2
	if !strict(bytes.TrimRight(header, "\x00"), &h) {
		return recordV2{}, nil, ErrUnavailable
	}
	raw, err := json.Marshal(h.Record)
	if err != nil || digest(raw) != h.Checksum || !p.validRecord(h.Record, index) {
		return recordV2{}, nil, ErrUnavailable
	}
	data := make([]byte, h.Record.Length)
	if len(data) > 0 {
		if _, err = f.ReadAt(data, offset+headerV2); err != nil {
			return recordV2{}, nil, ErrUnavailable
		}
	}
	if digest(data) != h.Record.Digest {
		return recordV2{}, nil, ErrUnavailable
	}
	return h.Record, data, nil
}

func (p *PoolV2) follows(old, next recordV2) bool {
	if old.Sequence == ^uint64(0) || next.Sequence != old.Sequence+1 {
		return false
	}
	switch next.State {
	case "claimed":
		return old.State == "ready" && old.Epoch == next.Epoch
	case "written":
		return old.State == "claimed" && p.claimRecord(old) == p.claimRecord(next)
	case "retired_held":
		if next.Retirement == nil {
			return false
		}
		e := next.Retirement.Expected
		if e.Written == nil {
			return old.State == "claimed" && p.claimRecord(old) == e.Claim
		}
		return old.State == "written" && p.bindingRecord(old) == *e.Written
	case "free_prepared":
		return old.State == "retired_held" && reflect.DeepEqual(old.Retirement, next.Retirement)
	case "ready":
		return old.State == "free_prepared" && reflect.DeepEqual(old.Retirement, next.Retirement)
	}
	return false
}

func (p *PoolV2) inspect(index int) (inspectionV2, error) {
	a, ad, ae := p.readBank(index, 0)
	b, bd, be := p.readBank(index, 1)
	if ae != nil || be != nil {
		return inspectionV2{}, ErrUnavailable
	}
	return p.resolveBanksV2(a, ad, b, bd)
}

func (p *PoolV2) resolveBanksV2(a recordV2, ad []byte, b recordV2, bd []byte) (inspectionV2, error) {
	// No recovery write or allocation is authorized by an unknown/torn bank.
	if a.Slot != b.Slot {
		return inspectionV2{}, ErrUnavailable
	}
	if a.Sequence == b.Sequence {
		if !reflect.DeepEqual(a, b) || !bytes.Equal(ad, bd) {
			return inspectionV2{}, ErrUnavailable
		}
		return inspectionV2{a, ad, true}, nil
	}
	if a.Sequence > b.Sequence {
		if !p.follows(b, a) {
			return inspectionV2{}, ErrUnavailable
		}
		return inspectionV2{a, ad, false}, nil
	}
	if !p.follows(a, b) {
		return inspectionV2{}, ErrUnavailable
	}
	return inspectionV2{b, bd, false}, nil
}

func (p *PoolV2) identity() error {
	if p == nil || p.root == nil || p.rootInfo == nil || p.lock == nil || p.lockInfo == nil || !validManifestV2(p.manifest) || len(p.slots) != p.manifest.Slots {
		return ErrUnavailable
	}
	root, err := p.root.Stat(".")
	if err != nil || !os.SameFile(root, p.rootInfo) || !accessDirectoryV2(p.root, root, p.access) {
		return ErrUnavailable
	}
	named, err := p.root.Lstat("pool.json")
	if err != nil || !os.SameFile(named, p.lockInfo) || !accessFileV2(p.lock, named, root, p.access) {
		return ErrUnavailable
	}
	for i, s := range p.slots {
		if s.file == nil || s.info == nil {
			return ErrUnavailable
		}
		info, err := s.file.Stat()
		if err != nil || !os.SameFile(info, s.info) || !accessFileV2(s.file, info, root, p.access) || info.Size() != 2*bankSizeV2(p.manifest.Capacity) || !fullyAllocated(info) {
			return ErrUnavailable
		}
		named, err = p.root.Lstat(slotName(i))
		if err != nil || !os.SameFile(named, info) || !accessFileV2(s.file, named, root, p.access) || named.Size() != info.Size() {
			return ErrUnavailable
		}
	}
	return nil
}

func (p *PoolV2) ready() error {
	if p.closed || p.blocked || p.readOnly || p.identity() != nil {
		return ErrUnavailable
	}
	return nil
}
func (p *PoolV2) point(name string) error {
	if p.hook != nil {
		return p.hook(name)
	}
	return nil
}

func (p *PoolV2) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var result error
	for _, s := range p.slots {
		if s.file != nil && s.file.Close() != nil {
			result = ErrUnavailable
		}
	}
	if p.lock != nil && p.lock.Close() != nil {
		result = ErrUnavailable
	}
	return result
}
