// Package recoveryreserve provides a bounded, preallocated recovery byte pool.
// It does not select configuration, retire audit or grant recovery authority.
package recoveryreserve

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

var (
	ErrInvalid     = errors.New("ANDEIVA_RESERVE_INVALID")
	ErrUnavailable = errors.New("ANDEIVA_RESERVE_UNAVAILABLE")
	ErrFull        = errors.New("ANDEIVA_RESERVE_FULL")
	ErrConflict    = errors.New("ANDEIVA_RESERVE_CONFLICT")
)

const format = "andeiva.recovery.reserve.v1"
const headerBytes = 1024

type manifest struct {
	Format   string `json:"format"`
	ID       string `json:"id"`
	Slots    int    `json:"slots"`
	Capacity int    `json:"capacity"`
}

type record struct {
	Format   string `json:"format"`
	Pool     string `json:"pool"`
	Sequence uint64 `json:"sequence,string"`
	Owner    string `json:"owner"`
	Length   int    `json:"length"`
	Digest   string `json:"digest"`
}

type diskHeader struct {
	Record   record `json:"record"`
	Checksum string `json:"checksum"`
}

type slot struct {
	file    *os.File
	info    os.FileInfo
	current record
}

// Lease is a process-local compare-and-swap witness, not an authorization token.
// The configuration coordinator must durably bind Owner before using the bytes.
type Lease struct {
	pool     *Pool
	index    int
	owner    string
	sequence uint64
}

// Binding is persisted by the owning coordinator alongside its durable intent.
// Matching an owner alone does not prove that the expected record survived.
type Binding struct {
	Pool     string `json:"pool"`
	Slot     int    `json:"slot"`
	Owner    string `json:"owner"`
	Sequence uint64 `json:"sequence,string"`
	Digest   string `json:"digest"`
}

func (Lease) String() string   { return "<recovery reserve lease>" }
func (Lease) GoString() string { return "<recovery reserve lease>" }

type Pool struct {
	mu              sync.Mutex
	root            *os.Root
	rootInfo        os.FileInfo
	lock            *os.File
	lockInfo        os.FileInfo
	manifest        manifest
	slots           []slot
	closed, blocked bool
	hook            func(string) error
}

func validProfile(slots, capacity int) bool {
	return slots >= 1 && slots <= 32 && capacity >= 4096 && capacity <= 1<<20 && capacity%4096 == 0
}

func strict(data []byte, target any) bool {
	if !jsoncheck.UniqueControlFields(data) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return false
	}
	return d.Decode(new(any)) == io.EOF
}

func digest(data []byte) string   { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func slotName(index int) string   { return fmt.Sprintf("reserve-%02d.bin", index) }
func bankSize(capacity int) int64 { return (int64(headerBytes+capacity) + 4095) / 4096 * 4096 }

// Prepare requires an empty private area. A partial preparation is retained for
// inspection; it never deletes files or overwrites an existing pool.
func Prepare(area *os.Root, slots, capacity int) (*Pool, error) {
	if area == nil || !validProfile(slots, capacity) {
		return nil, ErrInvalid
	}
	if err := platform(); err != nil {
		return nil, err
	}
	info, err := area.Stat(".")
	if err != nil || !privateDirectory(info) {
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
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, ErrUnavailable
	}
	m := manifest{format, hex.EncodeToString(id[:]), slots, capacity}
	for i := 0; i < slots; i++ {
		f, e := createFile(area, slotName(i))
		if e != nil {
			return nil, ErrUnavailable
		}
		e = allocate(f, 2*bankSize(capacity))
		if e == nil {
			r := record{Format: format, Pool: m.ID, Sequence: 1, Digest: digest(nil)}
			for bank := 0; bank < 2 && e == nil; bank++ {
				e = writeHeader(f, int64(bank)*bankSize(capacity), r)
			}
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
	f, err := createFile(area, "pool.json")
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
	return Open(area)
}

// Open borrows area and keeps an exclusive lock until Close. Files and payload
// allocations are prepared already; Claim/Write create no paths or new inodes.
func Open(area *os.Root) (pool *Pool, result error) {
	if area == nil {
		return nil, ErrInvalid
	}
	if err := platform(); err != nil {
		return nil, err
	}
	info, err := area.Stat(".")
	if err != nil || !privateDirectory(info) {
		return nil, ErrUnavailable
	}
	p := &Pool{root: area, rootInfo: info}
	defer func() {
		if result != nil {
			_ = p.Close()
		}
	}()
	p.lock, err = openFile(area, "pool.json")
	if err != nil {
		return nil, ErrUnavailable
	}
	p.lockInfo, err = p.lock.Stat()
	if err != nil || !privateFile(p.lockInfo, info) || p.lockInfo.Size() < 1 || p.lockInfo.Size() > 4096 || lock(p.lock) != nil {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(p.lock, 4097))
	if err != nil || len(data) > 4096 || !strict(data, &p.manifest) || p.manifest.Format != format || !validProfile(p.manifest.Slots, p.manifest.Capacity) || len(p.manifest.ID) != 32 {
		return nil, ErrUnavailable
	}
	id, err := hex.DecodeString(p.manifest.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != p.manifest.ID {
		return nil, ErrUnavailable
	}
	dir, err := area.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	entries, err := dir.ReadDir(p.manifest.Slots + 2)
	closeErr := dir.Close()
	if (err != nil && err != io.EOF) || closeErr != nil || len(entries) != p.manifest.Slots+1 {
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
	owners := make(map[string]bool)
	for i := 0; i < p.manifest.Slots; i++ {
		f, e := openFile(area, slotName(i))
		if e != nil {
			return nil, ErrUnavailable
		}
		p.slots = append(p.slots, slot{file: f})
		s := &p.slots[i]
		s.info, e = f.Stat()
		if e != nil || !privateFile(s.info, info) || s.info.Size() != 2*bankSize(p.manifest.Capacity) || !fullyAllocated(s.info) {
			return nil, ErrUnavailable
		}
		r, _, e := p.readSlot(i)
		if e != nil || (r.Owner != "" && owners[r.Owner]) {
			return nil, ErrUnavailable
		}
		if r.Owner != "" {
			owners[r.Owner] = true
		}
		s.current = r
	}
	if p.identity() != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}

func writeHeader(f *os.File, offset int64, r record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	data, err := json.Marshal(diskHeader{r, digest(raw)})
	if err != nil || len(data) >= headerBytes {
		return ErrUnavailable
	}
	header := make([]byte, headerBytes)
	copy(header, data)
	n, err := f.WriteAt(header, offset)
	if err != nil || n != len(header) {
		return ErrUnavailable
	}
	return nil
}

func (p *Pool) readBank(index, bank int) (record, []byte, error) {
	var h diskHeader
	f := p.slots[index].file
	offset := int64(bank) * bankSize(p.manifest.Capacity)
	header := make([]byte, headerBytes)
	if _, err := f.ReadAt(header, offset); err != nil {
		return record{}, nil, ErrUnavailable
	}
	data := bytes.TrimRight(header, "\x00")
	if !strict(data, &h) {
		return record{}, nil, ErrUnavailable
	}
	r := h.Record
	raw, err := json.Marshal(r)
	if err != nil || digest(raw) != h.Checksum || r.Format != format || r.Pool != p.manifest.ID || r.Sequence == 0 || r.Length < 0 || r.Length > p.manifest.Capacity || !validOwner(r.Owner) || (r.Owner == "" && r.Length != 0) {
		return record{}, nil, ErrUnavailable
	}
	payload := make([]byte, r.Length)
	if len(payload) > 0 {
		if _, err := f.ReadAt(payload, offset+headerBytes); err != nil {
			return record{}, nil, ErrUnavailable
		}
	}
	if digest(payload) != r.Digest {
		return record{}, nil, ErrUnavailable
	}
	return r, payload, nil
}

func (p *Pool) readSlot(index int) (record, []byte, error) {
	a, ad, ae := p.readBank(index, 0)
	b, bd, be := p.readBank(index, 1)
	if ae != nil && be != nil {
		return record{}, nil, ErrUnavailable
	}
	if ae == nil && be == nil && a.Sequence == b.Sequence && (a != b || !bytes.Equal(ad, bd)) {
		return record{}, nil, ErrUnavailable
	}
	// A damaged first claim must not turn a previously reserved inode into a
	// free slot. Only the original, identical pair establishes unused space.
	if (ae == nil && a.Owner == "") || (be == nil && b.Owner == "") {
		if ae != nil || be != nil {
			return record{}, nil, ErrUnavailable
		}
	}
	if be != nil || (ae == nil && a.Sequence >= b.Sequence) {
		return a, ad, nil
	}
	return b, bd, nil
}

func validOwner(owner string) bool {
	if len(owner) > 128 {
		return false
	}
	for _, r := range owner {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func (p *Pool) identity() error {
	if p == nil || p.root == nil || p.rootInfo == nil || p.lock == nil || p.lockInfo == nil ||
		!validProfile(p.manifest.Slots, p.manifest.Capacity) || len(p.slots) != p.manifest.Slots {
		return ErrUnavailable
	}
	root, err := p.root.Stat(".")
	if err != nil || !os.SameFile(root, p.rootInfo) || !privateDirectory(root) {
		return ErrUnavailable
	}
	info, err := p.root.Lstat("pool.json")
	if err != nil || !os.SameFile(info, p.lockInfo) || !privateFile(info, root) {
		return ErrUnavailable
	}
	for i, s := range p.slots {
		info, err = p.root.Lstat(slotName(i))
		if err != nil || !os.SameFile(info, s.info) || !privateFile(info, root) || info.Size() != s.info.Size() {
			return ErrUnavailable
		}
	}
	return nil
}

func (p *Pool) ready() error {
	if p.closed || p.blocked || p.identity() != nil {
		return ErrUnavailable
	}
	return nil
}

func (p *Pool) Claim(owner string) (Lease, error) {
	if p == nil || owner == "" || !validOwner(owner) {
		return Lease{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return Lease{}, ErrUnavailable
	}
	for i, s := range p.slots {
		if s.current.Owner == owner {
			return Lease{p, i, owner, s.current.Sequence}, nil
		}
	}
	for i, s := range p.slots {
		if s.current.Owner == "" {
			return p.store(i, owner, nil)
		}
	}
	return Lease{}, ErrFull
}

func (p *Pool) Write(lease Lease, payload []byte) (Lease, error) {
	if p == nil {
		return Lease{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return Lease{}, ErrUnavailable
	}
	if lease.pool != p || lease.index < 0 || lease.index >= len(p.slots) || lease.owner == "" || p.slots[lease.index].current.Owner != lease.owner || p.slots[lease.index].current.Sequence != lease.sequence {
		return Lease{}, ErrConflict
	}
	if len(payload) > p.manifest.Capacity {
		return Lease{}, ErrInvalid
	}
	return p.store(lease.index, lease.owner, payload)
}

func (p *Pool) point(name string) error {
	if p.hook != nil {
		return p.hook(name)
	}
	return nil
}

func (p *Pool) store(index int, owner string, payload []byte) (Lease, error) {
	s := &p.slots[index]
	observed, _, readErr := p.readSlot(index)
	if readErr != nil || observed != s.current {
		p.blocked = true
		return Lease{}, ErrUnavailable
	}
	if s.current.Sequence == ^uint64(0) {
		return Lease{}, ErrFull
	}
	r := record{format, p.manifest.ID, s.current.Sequence + 1, owner, len(payload), digest(payload)}
	bank := int(r.Sequence % 2)
	offset := int64(bank) * bankSize(p.manifest.Capacity)
	if len(payload) > 0 {
		n, err := s.file.WriteAt(payload, offset+headerBytes)
		if err != nil || n != len(payload) {
			p.blocked = true
			return Lease{}, ErrUnavailable
		}
	}
	if s.file.Sync() != nil || p.point("payload_synced") != nil {
		p.blocked = true
		return Lease{}, ErrUnavailable
	}
	if writeHeader(s.file, offset, r) != nil || p.point("header_written") != nil || s.file.Sync() != nil || p.point("header_synced") != nil {
		p.blocked = true
		return Lease{}, ErrUnavailable
	}
	actual, actualData, err := p.readSlot(index)
	if err != nil || actual != r || !bytes.Equal(actualData, payload) || p.identity() != nil {
		p.blocked = true
		return Lease{}, ErrUnavailable
	}
	s.current = r
	return Lease{p, index, owner, r.Sequence}, nil
}

// Read returns a copy of retained recovery bytes. Claims are never recycled by
// age, a caller boolean, or a full disk. Retirement requires coordinator binding.
func (p *Pool) Read(owner string) ([]byte, error) {
	if p == nil || owner == "" || !validOwner(owner) {
		return nil, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.identity() != nil {
		return nil, ErrUnavailable
	}
	for i, s := range p.slots {
		if s.current.Owner == owner {
			r, data, err := p.readSlot(i)
			if err != nil || r.Owner != owner {
				return nil, ErrUnavailable
			}
			return data, nil
		}
	}
	return nil, ErrConflict
}

func (p *Pool) Binding(lease Lease) (Binding, error) {
	if p == nil {
		return Binding{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready() != nil {
		return Binding{}, ErrUnavailable
	}
	if lease.pool != p || lease.index < 0 || lease.index >= len(p.slots) {
		return Binding{}, ErrConflict
	}
	r, _, err := p.readSlot(lease.index)
	if err != nil || r.Owner != lease.owner || r.Sequence != lease.sequence || r.Owner == "" {
		return Binding{}, ErrConflict
	}
	return Binding{p.manifest.ID, lease.index, r.Owner, r.Sequence, r.Digest}, nil
}

// ReadBound refuses an older valid bank when the selected transaction expects a
// later record. A fallback bank is never silently promoted to durable success.
func (p *Pool) ReadBound(binding Binding) ([]byte, error) {
	if p == nil || binding.Owner == "" || !validOwner(binding.Owner) || binding.Sequence == 0 {
		return nil, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.identity() != nil {
		return nil, ErrUnavailable
	}
	if binding.Pool != p.manifest.ID || binding.Slot < 0 || binding.Slot >= len(p.slots) {
		return nil, ErrConflict
	}
	r, data, err := p.readSlot(binding.Slot)
	if err != nil || r.Owner != binding.Owner || r.Sequence != binding.Sequence || r.Digest != binding.Digest {
		return nil, ErrUnavailable
	}
	return data, nil
}

func (p *Pool) Close() error {
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
		if s.file.Close() != nil {
			result = ErrUnavailable
		}
	}
	if p.lock != nil && p.lock.Close() != nil {
		result = ErrUnavailable
	}
	return result
}
