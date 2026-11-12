//go:build linux

package authobservations

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hexValue(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}

// Prepare selects a new anonymous-only area. The caller supplies fingerprints
// already checked by the runtime guard; no pathname or cleanup policy is accepted.
func Prepare(area *os.Root, runtime, protected, backup string, guard AdmissionGuard) error {
	if area == nil || guard == nil || !hexValue(runtime, 32) || !hexValue(protected, 32) || backup != protected {
		return ErrInvalid
	}
	id, err := identity(area)
	if err != nil {
		return err
	}
	dir, err := area.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	entries, e := dir.ReadDir(1)
	closeErr := dir.Close()
	if e != io.EOF || len(entries) != 0 || closeErr != nil {
		return ErrUnavailable
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrUnavailable
	}
	p := Selection{Version: 1, Feature: Feature, ID: hex.EncodeToString(nonce[:]), Runtime: runtime, Protected: protected, Backup: backup, Area: id}
	if guard.Selection(p) != nil || guard.Capacity(id, 0, MaximumBytes) != nil || available(area, MaximumBytes) != nil {
		return ErrUnavailable
	}
	lock, err := area.OpenFile("lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer lock.Close()
	if lock.Chmod(0600) != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || lock.Sync() != nil {
		return ErrUnavailable
	}
	initial := snapshot{Version: 1, Policy: p.ID, Generation: 1, At: time.Now().UTC(), Intervals: []Interval{}}
	body, err := snapshotBytes(initial)
	if err != nil || writeNew(area, "observations.json", body) != nil {
		return ErrUnavailable
	}
	policy, err := json.Marshal(p)
	if err != nil || writeNew(area, "policy.next", policy) != nil {
		return ErrUnavailable
	}
	// Admission is rechecked immediately before the atomic policy selection.
	if guard.Selection(p) != nil || area.Rename("policy.next", "policy.json") != nil || syncDir(area) != nil {
		return ErrUnavailable
	}
	_, err = measure(area, p.Area)
	return err
}

func Open(area *os.Root, guard AdmissionGuard) (*Store, error) {
	if area == nil || guard == nil {
		return nil, ErrInvalid
	}
	id, err := identity(area)
	if err != nil {
		return nil, err
	}
	lock, err := area.OpenFile("lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	fail := func(e error) (*Store, error) { _ = lock.Close(); return nil, e }
	li, err := lock.Stat()
	if err != nil || !regular(li, id, 0) || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !sameLock(area, lock, id) {
		return fail(ErrUnavailable)
	}
	policy, err := read(area, "policy.json", id, 4096)
	var p Selection
	if err != nil || decode(policy, &p) != nil || !validSelection(p, id) || guard.Selection(p) != nil {
		return fail(ErrUnavailable)
	}
	allocated, err := measure(area, id)
	if err != nil {
		return fail(err)
	}
	body, err := read(area, "observations.json", id, maximumSnapshot)
	if err != nil {
		return fail(err)
	}
	data, err := decodeSnapshot(body, p.ID)
	if err != nil {
		return fail(err)
	}
	// An interrupted temporary is never blindly deleted or promoted. Its
	// ownership/format and next-generation relation must be proven first.
	if _, e := area.Lstat("observations.next"); e == nil {
		b, e := read(area, "observations.next", id, maximumSnapshot)
		next, ne := decodeSnapshot(b, p.ID)
		if e != nil || ne != nil || data.Generation == ^uint64(0) || next.Generation != data.Generation+1 {
			return fail(ErrUnavailable)
		}
		if area.Remove("observations.next") != nil || syncDir(area) != nil {
			return fail(ErrUnavailable)
		}
	} else if !os.IsNotExist(e) {
		return fail(ErrUnavailable)
	}
	s := &Store{root: area, lock: lock, policy: p, guard: guard, data: data, last: data.At, persisted: data.At, allocated: allocated, now: time.Now, unknown: true, selectedDigest: digest(body), policyDigest: digest(policy)}
	for _, interval := range data.Intervals {
		s.peers += len(interval.Peers)
	}
	s.expire(s.now().UTC())
	// A full/read-only observation budget is degraded collection, not loss of
	// protected authentication authority. Runtime selection itself must verify.
	if guard.Capacity(id, allocated, maximumSnapshot+65536) != nil || available(area, maximumSnapshot+65536) != nil {
		s.degraded = true
	}
	s.start()
	return s, nil
}

// OpenDegraded requires the canonical selection from independent trusted runtime
// state, never one inferred from unreadable observation files. It cannot publish,
// delete or repair anything. This preserves protected authentication availability
// without silently restoring legacy classification or trusting corrupt detail.
func OpenDegraded(area *os.Root, canonical Selection, guard AdmissionGuard) (*Store, error) {
	if area == nil || guard == nil {
		return nil, ErrInvalid
	}
	id, err := identity(area)
	if err != nil || !validSelection(canonical, id) || guard.Selection(canonical) != nil {
		return nil, ErrUnavailable
	}
	now := time.Now().UTC()
	return &Store{root: area, policy: canonical, guard: guard, data: snapshot{Version: 1, Policy: canonical.ID, Intervals: []Interval{}}, last: now, now: time.Now, degraded: true, unknown: true, memoryOnly: true}, nil
}

func validSelection(p Selection, id AreaIdentity) bool {
	return p.Version == 1 && p.Feature == Feature && hexValue(p.ID, 16) && hexValue(p.Runtime, 32) && hexValue(p.Protected, 32) && p.Backup == p.Protected && p.Area == id
}

func (s *Store) publish(ctx context.Context, data snapshot) (allocated uint64, touched bool, result error) {
	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	body, err := snapshotBytes(data)
	if err != nil {
		return 0, false, err
	}
	id, err := identity(s.root)
	if err != nil || id != s.policy.Area || !sameLock(s.root, s.lock, id) || s.guard.Selection(s.policy) != nil {
		return 0, false, ErrUnavailable
	}
	allocated, err = measure(s.root, id)
	if err != nil {
		return 0, false, err
	}
	current, err := read(s.root, "observations.json", id, maximumSnapshot)
	policy, policyErr := read(s.root, "policy.json", id, 4096)
	if err != nil || policyErr != nil || digest(current) != s.selectedDigest || digest(policy) != s.policyDigest {
		return allocated, false, ErrUnavailable
	}
	// Include coexistence with the temporary and an explicit metadata allowance.
	peak := uint64(len(body)) + 65536
	if allocated > MaximumBytes || peak > MaximumBytes-allocated {
		return allocated, false, ErrLimited
	}
	if s.guard.Capacity(id, allocated, peak) != nil || available(s.root, peak) != nil {
		return allocated, false, ErrLimited
	}
	if err := s.point("before_temporary"); err != nil {
		return allocated, false, err
	}
	if err := writeNew(s.root, "observations.next", body); err != nil {
		return allocated, true, err
	}
	if err := s.point("after_temporary_sync"); err != nil {
		return allocated, true, err
	}
	if err := ctx.Err(); err != nil {
		return allocated, true, err
	}
	if s.root.Rename("observations.next", "observations.json") != nil {
		return allocated, true, ErrUnavailable
	}
	if err := s.point("after_rename"); err != nil {
		return allocated, true, err
	}
	if syncDir(s.root) != nil {
		return allocated, true, ErrUnavailable
	}
	if err := s.point("after_directory_sync"); err != nil {
		return allocated, true, err
	}
	allocated, err = measure(s.root, id)
	if err == nil {
		s.selectedDigest = digest(body)
	}
	return allocated, true, err
}

func writeNew(root *os.Root, name string, body []byte) (result error) {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if f.Close() != nil && result == nil {
			result = ErrUnavailable
		}
	}()
	if f.Chmod(0600) != nil {
		return ErrUnavailable
	}
	n, err := f.Write(body)
	if err != nil || n != len(body) || f.Sync() != nil {
		return ErrUnavailable
	}
	return syncDir(root)
}

func identity(root *os.Root) (AreaIdentity, error) {
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return AreaIdentity{}, ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		return AreaIdentity{}, ErrUnavailable
	}
	return AreaIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

func regular(info os.FileInfo, area AreaIdentity, limit int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > limit {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Geteuid()) && uint64(st.Dev) == area.Device && st.Nlink == 1
}

func sameLock(root *os.Root, lock *os.File, area AreaIdentity) bool {
	if lock == nil {
		return false
	}
	held, err := lock.Stat()
	named, namedErr := root.Lstat("lock")
	return err == nil && namedErr == nil && regular(held, area, 0) && regular(named, area, 0) && os.SameFile(held, named)
}

func read(root *os.Root, name string, area AreaIdentity, limit int64) (body []byte, result error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if f.Close() != nil && result == nil {
			result = ErrUnavailable
		}
	}()
	before, err := f.Stat()
	if err != nil || !regular(before, area, limit) {
		return nil, ErrUnavailable
	}
	body, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != before.Size() {
		return nil, ErrUnavailable
	}
	after, err := f.Stat()
	named, ne := root.Lstat(name)
	if err != nil || ne != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || !regular(after, area, limit) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrUnavailable
	}
	return body, nil
}

func syncDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	e := d.Sync()
	ce := d.Close()
	if e != nil || ce != nil {
		return ErrUnavailable
	}
	return nil
}

func measure(root *os.Root, area AreaIdentity) (uint64, error) {
	dir, err := root.Open(".")
	if err != nil {
		return 0, ErrUnavailable
	}
	defer dir.Close()
	entries, err := dir.ReadDir(5)
	if (err != nil && err != io.EOF) || len(entries) > 4 {
		return 0, ErrUnavailable
	}
	info, err := dir.Stat()
	if err != nil {
		return 0, ErrUnavailable
	}
	allocated, err := blocks(info)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "lock" && name != "policy.json" && name != "observations.json" && name != "observations.next" {
			return 0, ErrUnavailable
		}
		info, e := root.Lstat(name)
		if e != nil || !regular(info, area, maximumSnapshot) {
			return 0, ErrUnavailable
		}
		n, e := blocks(info)
		if e != nil || n > MaximumBytes-allocated {
			return 0, ErrLimited
		}
		allocated += n
	}
	return allocated, nil
}

func blocks(info os.FileInfo) (uint64, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Blocks < 0 || st.Blocks > int64(MaximumBytes/512) {
		return 0, ErrLimited
	}
	return uint64(st.Blocks) * 512, nil
}

func available(root *os.Root, required uint64) error {
	dir, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	var st syscall.Statfs_t
	if syscall.Fstatfs(int(dir.Fd()), &st) != nil || st.Bsize <= 0 || st.Bsize > 1<<20 || st.Flags&1 != 0 || st.Ffree == 0 {
		return ErrLimited
	}
	unit := uint64(st.Bsize)
	if st.Bavail < (required+unit-1)/unit {
		return ErrLimited
	}
	return nil
}

func decode(body []byte, target any) error {
	keys := json.NewDecoder(bytes.NewReader(body))
	if unique(keys, 0) != nil {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}
func unique(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrUnavailable
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			k, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := k.(string)
			name = strings.ToLower(name)
			if !ok || seen[name] {
				return ErrUnavailable
			}
			seen[name] = true
		}
		if unique(d, depth+1) != nil {
			return ErrUnavailable
		}
	}
	_, err = d.Token()
	return err
}

func snapshotBytes(data snapshot) ([]byte, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded, err := json.Marshal(struct {
		Hash string          `json:"hash"`
		Data json.RawMessage `json:"data"`
	}{digest(body), body})
	if err != nil || len(encoded) > maximumSnapshot {
		return nil, ErrLimited
	}
	return encoded, nil
}

func decodeSnapshot(body []byte, policy string) (snapshot, error) {
	var wrapper struct {
		Hash string          `json:"hash"`
		Data json.RawMessage `json:"data"`
	}
	var data snapshot
	if decode(body, &wrapper) != nil || digest(wrapper.Data) != wrapper.Hash || decode(wrapper.Data, &data) != nil || data.Version != 1 || data.Policy != policy || data.Generation == 0 || data.At.IsZero() || data.At.Location() != time.UTC || len(data.Intervals) > maximumIntervals {
		return data, ErrUnavailable
	}
	peers := 0
	var last time.Time
	for _, interval := range data.Intervals {
		if interval.Minute.IsZero() || interval.Minute.Location() != time.UTC || interval.Created.Location() != time.UTC || interval.Minute != interval.Minute.Truncate(time.Minute) || !interval.Minute.After(last) || interval.Created.Before(interval.Minute) || !interval.Created.Before(interval.Minute.Add(time.Minute)) || interval.Created.After(data.At) {
			return data, ErrUnavailable
		}
		last = interval.Minute
		previous := ""
		total := interval.Overflow
		for _, p := range interval.Peers {
			addr, err := netip.ParseAddr(p.Peer)
			if err != nil || !validPeer(addr) || addr.Unmap().String() != p.Peer || p.Peer <= previous || p.Count == 0 || ^uint64(0)-total < p.Count {
				return data, ErrUnavailable
			}
			previous = p.Peer
			total += p.Count
			peers++
		}
		if total != interval.Total || peers > maximumPeers {
			return data, ErrUnavailable
		}
	}
	return data, nil
}
