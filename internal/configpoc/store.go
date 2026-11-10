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
	owner   []byte
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
func (s *fileStore) load() (result error) {
	root, err := s.openScopedRoot()
	if err != nil {
		return err
	}
	defer closeRoot(root, &result)
	directory, err := root.Open(".")
	if err != nil {
		return ErrStorage
	}
	entries, readErr := directory.ReadDir(s.limit + 4)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > s.limit+3 {
		return ErrStorage
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	registration, stage := false, false
	for _, entry := range entries {
		switch entry.Name() {
		case "state.lock":
			continue
		case stagingRegistration:
			registration = true
			continue
		case stagingDirectory:
			stage = true
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !regularOwned(info, maxRecordBytes) {
			return ErrStorage
		}
		s.bytes += info.Size()
		if s.bytes > maxJournalBytes || entry.Name() != fmt.Sprintf("%08d.json", len(s.records)+1) {
			return ErrStorage
		}
		data, err := root.ReadFile(entry.Name())
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
	// Adoption of a clean older journal happens only after complete validation.
	// Any partial ownership bootstrap is retained, never guessed or repaired.
	if !registration && !stage {
		return s.initializeStaging(root)
	}
	if !registration || !stage {
		return ErrStorage
	}
	payload, err := s.validateStaging(root)
	if err != nil {
		return err
	}
	if payload != nil {
		return s.removePayload(root, payload)
	}
	return nil
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
		if !identifier.MatchString(p.Owner) || p.Owner == "system" || p.Deadline.IsZero() || (p.Lease != "" && !identifier.MatchString(p.Lease)) {
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
func (s *fileStore) append(state durableState, audit Audit, critical bool, hook func(string) error) (result error) {
	root, err := s.openScopedRoot()
	if err != nil {
		return err
	}
	defer closeRoot(root, &result)
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
	if payload, err := s.validateStaging(root); err != nil || payload != nil {
		return ErrStorage
	}
	if hook != nil {
		if err = hook("before_persist"); err != nil {
			return err
		}
	}
	tempName := filepath.Join(stagingDirectory, stagingPayload)
	temp, err := root.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrStorage
	}
	created, err := temp.Stat()
	if err != nil || !regularOwned(created, maxRecordBytes) {
		_ = temp.Close()
		return ErrStorage
	}
	published := false
	defer func() {
		_ = temp.Close()
		if !published {
			_ = s.removePayload(root, created)
		}
	}()
	if err = stageHook(hook, "after_stage_create"); err != nil {
		return err
	}
	middle := len(data) / 2
	if _, err = temp.Write(data[:middle]); err != nil {
		return ErrStorage
	}
	if err = stageHook(hook, "after_stage_partial_write"); err != nil {
		return err
	}
	if _, err = temp.Write(data[middle:]); err != nil {
		return ErrStorage
	}
	if err = temp.Sync(); err != nil {
		return ErrStorage
	}
	if err = stageHook(hook, "after_stage_sync"); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return ErrStorage
	}
	final := fmt.Sprintf("%08d.json", len(s.records)+1)
	if err = stageHook(hook, "before_publish"); err != nil {
		return err
	}
	payload, err := s.validateStaging(root)
	if err != nil || payload == nil || !os.SameFile(payload, created) {
		return ErrStorage
	}
	if _, err = root.Lstat(final); !os.IsNotExist(err) {
		return ErrStorage
	}
	if err = root.Rename(tempName, final); err != nil {
		return ErrStorage
	}
	published = true
	if hook != nil {
		if err = hook("after_rename"); err != nil {
			return err
		}
	}
	if err = syncDirectory(root, "."); err != nil {
		return err
	}
	if err = syncDirectory(root, stagingDirectory); err != nil {
		return err
	}
	s.records = append(s.records, record)
	s.bytes += int64(len(data))
	return nil
}
