package configpoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxRecordBytes = 1024 * 1024
const maxJournalBytes = 64 * 1024 * 1024
const maxPendingFiles = 128

type receipt struct {
	Fingerprint string `json:"fingerprint"`
	Generation  uint64 `json:"generation"`
}
type durableState struct {
	Snapshot Snapshot           `json:"snapshot"`
	Intent   *Intent            `json:"intent,omitempty"`
	Receipts map[string]receipt `json:"receipts"`
}
type journalRecord struct {
	Previous string       `json:"previous"`
	State    durableState `json:"state"`
	Audit    Audit        `json:"audit"`
	Hash     string       `json:"hash"`
}
type fileStore struct {
	dir     string
	lock    *os.File
	records []journalRecord
	bytes   int64
	limit   int
}

func openStore(dir string, limit int) (*fileStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(filepath.Separator) {
		return nil, ErrInvalid
	}
	for part := dir; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrStorage
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, ErrStorage
		}
		if part == filepath.Dir(part) {
			break
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, ErrStorage
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return nil, ErrStorage
	}
	lock, err := lockStore(filepath.Join(dir, "state.lock"))
	if err != nil {
		return nil, err
	}
	s := &fileStore{dir: dir, lock: lock, limit: limit}
	if err = s.load(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return s, nil
}
func (s *fileStore) load() error {
	directory, err := os.Open(s.dir)
	if err != nil {
		return ErrStorage
	}
	entries, readErr := directory.ReadDir(s.limit + maxPendingFiles + 2)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > s.limit+maxPendingFiles+1 {
		return ErrStorage
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	type pendingFile struct {
		name string
		info os.FileInfo
	}
	var pending []pendingFile
	for _, entry := range entries {
		if entry.Name() == "state.lock" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) || info.Size() > maxRecordBytes {
			return ErrStorage
		}
		// Only the store's bounded, unacknowledged staging files are eligible for
		// cleanup. Do not remove anything until the complete committed chain is valid.
		if strings.HasPrefix(entry.Name(), ".pending-") {
			if !pendingName(entry.Name()) || len(pending) >= maxPendingFiles {
				return ErrStorage
			}
			pending = append(pending, pendingFile{name: entry.Name(), info: info})
			continue
		}
		s.bytes += info.Size()
		if s.bytes > maxJournalBytes {
			return ErrStorage
		}
		if entry.Name() != fmt.Sprintf("%08d.json", len(s.records)+1) || info.Size() > maxRecordBytes {
			return ErrStorage
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return ErrStorage
		}
		var record journalRecord
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
			return ErrStorage
		}
		previous := ""
		if len(s.records) > 0 {
			previous = s.records[len(s.records)-1].Hash
		}
		if record.Previous != previous || record.Audit.Sequence != uint64(len(s.records)+1) || record.Hash != recordHash(record) || !validState(record.State) {
			return ErrStorage
		}
		s.records = append(s.records, record)
		if len(s.records) > s.limit {
			return ErrStorage
		}
	}
	// The exclusive store lock prevents a cooperating writer from adding or changing
	// staging files. Recheck metadata before deleting exactly the validated names.
	for _, file := range pending {
		info, err := os.Lstat(filepath.Join(s.dir, file.name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) || info.Size() != file.info.Size() || !os.SameFile(info, file.info) {
			return ErrStorage
		}
	}
	for _, file := range pending {
		if err := os.Remove(filepath.Join(s.dir, file.name)); err != nil {
			return ErrStorage
		}
	}
	if len(pending) > 0 {
		directory, err := os.Open(s.dir)
		if err != nil {
			return ErrStorage
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return ErrStorage
		}
	}
	return nil
}

func pendingName(name string) bool {
	suffix := strings.TrimPrefix(name, ".pending-")
	if len(suffix) == 0 || len(suffix) > 10 {
		return false
	}
	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
func validState(s durableState) bool {
	if s.Snapshot.Generation == 0 || s.Snapshot.ReplayedGeneration != 0 || s.Receipts == nil || len(s.Receipts) > 1024 || len(s.Snapshot.Revoked) > 128 {
		return false
	}
	for key, receipt := range s.Receipts {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || !identifier.MatchString(parts[0]) || parts[0] == "system" || !identifier.MatchString(parts[1]) || !validHash(receipt.Fingerprint) || receipt.Generation == 0 || receipt.Generation > s.Snapshot.Generation {
			return false
		}
	}
	seen := map[string]bool{}
	for _, id := range s.Snapshot.Revoked {
		if !identifier.MatchString(id) || id == "system" || seen[id] {
			return false
		}
		seen[id] = true
	}
	if c := s.Snapshot.Candidate; c != nil {
		if !identifier.MatchString(c.Owner) || c.Owner == "system" || !validHash(c.Base) {
			return false
		}
	}
	if p := s.Snapshot.Pending; p != nil {
		if !identifier.MatchString(p.Owner) || p.Owner == "system" || p.Deadline.IsZero() {
			return false
		}
	}
	revisions := []Revision{s.Snapshot.Running, s.Snapshot.Startup, s.Snapshot.LastGood}
	if s.Snapshot.Candidate != nil {
		revisions = append(revisions, s.Snapshot.Candidate.Revision)
	}
	if s.Snapshot.Pending != nil {
		revisions = append(revisions, s.Snapshot.Pending.Previous)
	}
	if s.Intent != nil {
		revisions = append(revisions, s.Intent.Previous, s.Intent.Target)
	}
	for _, r := range revisions {
		canonical, err := Canonical(r.Config)
		if err != nil || canonical.Hash != r.Hash {
			return false
		}
	}
	return true
}
func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
func recordHash(r journalRecord) string {
	r.Hash = ""
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (s *fileStore) capacity(reserve int) bool {
	return len(s.records)+reserve < s.limit && s.bytes+int64(reserve+1)*maxRecordBytes <= maxJournalBytes
}
func (s *fileStore) append(state durableState, audit Audit, critical bool, hook func(string) error) error {
	reserve := 2
	if critical {
		reserve = 0
	}
	if !s.capacity(reserve) {
		return ErrStorage
	}
	previous := ""
	if len(s.records) > 0 {
		previous = s.records[len(s.records)-1].Hash
	}
	audit.Sequence = uint64(len(s.records) + 1)
	record := journalRecord{Previous: previous, State: clone(state), Audit: audit}
	record.Hash = recordHash(record)
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxRecordBytes {
		return ErrStorage
	}
	if hook != nil {
		if err = hook("before_persist"); err != nil {
			return err
		}
	}
	temp, err := os.CreateTemp(s.dir, ".pending-")
	if err != nil {
		return ErrStorage
	}
	tempName := temp.Name()
	defer func() { _ = temp.Close(); _ = os.Remove(tempName) }()
	if _, err = temp.Write(data); err != nil {
		return ErrStorage
	}
	if err = temp.Sync(); err != nil {
		return ErrStorage
	}
	if err = temp.Close(); err != nil {
		return ErrStorage
	}
	final := filepath.Join(s.dir, fmt.Sprintf("%08d.json", len(s.records)+1))
	if _, err = os.Lstat(final); !os.IsNotExist(err) {
		return ErrStorage
	}
	if err = os.Rename(tempName, final); err != nil {
		return ErrStorage
	}
	if hook != nil {
		if err = hook("after_rename"); err != nil {
			return err
		}
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return ErrStorage
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	s.records = append(s.records, record)
	s.bytes += int64(len(data))
	return nil
}
