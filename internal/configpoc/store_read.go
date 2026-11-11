package configpoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Only the last state is kept resident. Historical selection uses metadata
// established by complete validation at open, followed by a verified disk read.
type recordMetadata struct {
	Hash        string
	runningHash string
	confirmed   bool
	info        os.FileInfo
	audit       Audit
}

func metadata(record journalRecord, info os.FileInfo) recordMetadata {
	return recordMetadata{
		Hash: record.Hash, runningHash: record.State.Snapshot.Running.Hash,
		confirmed: record.State.Intent == nil && record.State.Snapshot.Pending == nil && !record.State.Snapshot.RecoveryRequired,
		info:      info,
		audit:     record.Audit,
	}
}

func sameRecordFile(expected, actual os.FileInfo) bool {
	return regularOwned(actual, maxRecordBytes) && os.SameFile(expected, actual) && expected.Size() == actual.Size() && expected.ModTime().Equal(actual.ModTime())
}

// readRecordData accepts a generated sequence, never a caller-controlled path. Both
// descriptor and path identities are checked around the bounded read, including
// the identity pinned when this journal was opened.
func readRecordData(root *os.Root, sequence uint64, expected os.FileInfo) (data []byte, verified os.FileInfo, result error) {
	name := fmt.Sprintf("%08d.json", sequence)
	before, err := root.Lstat(name)
	if err != nil || !sameRecordFile(expected, before) {
		return nil, nil, ErrStorage
	}
	file, err := openRecordFile(root, name)
	if err != nil {
		return nil, nil, ErrStorage
	}
	defer func() {
		if err := file.Close(); err != nil {
			result = ErrStorage
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameRecordFile(before, opened) {
		return nil, nil, ErrStorage
	}
	// Allocate for the verified size plus one byte to detect growth, never more
	// than the record limit plus one. Short reads and trailing bytes both fail.
	data = make([]byte, int(opened.Size())+1)
	n, err := io.ReadFull(file, data)
	if err != io.ErrUnexpectedEOF || int64(n) != opened.Size() {
		return nil, nil, ErrStorage
	}
	data = data[:n]
	after, err := file.Stat()
	if err != nil || !sameRecordFile(opened, after) {
		return nil, nil, ErrStorage
	}
	current, err := root.Lstat(name)
	if err != nil || !sameRecordFile(after, current) {
		return nil, nil, ErrStorage
	}
	return data, current, nil
}

func decodeRecord(data []byte, sequence uint64, previous, hash string) (record journalRecord, result error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || record.Previous != previous || record.Audit.Sequence != sequence || record.Hash != recordHash(record) || (hash != "" && record.Hash != hash) || !validState(record.State) {
		return journalRecord{}, ErrStorage
	}
	return record, nil
}

func (s *fileStore) readData(sequence uint64) (data []byte, result error) {
	if sequence == 0 || sequence > uint64(len(s.records)) {
		return nil, ErrInvalid
	}
	defer func() {
		if result != nil {
			s.readFailed = true
		}
	}()
	root, err := s.openScopedRoot()
	if err != nil {
		return nil, err
	}
	defer closeRoot(root, &result)
	meta := s.records[sequence-1]
	data, _, result = readRecordData(root, sequence, meta.info)
	return data, result
}

func (s *fileStore) read(sequence uint64) (journalRecord, error) {
	data, err := s.readData(sequence)
	if err != nil {
		return journalRecord{}, err
	}
	previous := ""
	if sequence > 1 {
		previous = s.records[sequence-2].Hash
	}
	record, err := decodeRecord(data, sequence, previous, s.records[sequence-1].Hash)
	if err != nil {
		s.readFailed = true
	}
	return record, err
}
