package configpoc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const stagingDirectory = ".andeiva-stage-v1"
const stagingRegistration = "staging-v1.owner"
const stagingMarker = "owner.json"
const stagingPayload = "record.tmp"
const maxMarkerBytes = 256

type stageOwner struct {
	Format  string `json:"format"`
	StoreID string `json:"store_id"`
}

func regularOwned(info os.FileInfo, limit int64) bool {
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && owned(info) && singleLink(info) && info.Size() <= limit
}

func (s *fileStore) openScopedRoot() (*os.Root, error) {
	if s.scopedRoot != nil {
		opened, err := s.scopedRoot.Stat(".")
		named, nameErr := os.Lstat(s.scopedRoot.Name())
		if err != nil || nameErr != nil || !opened.IsDir() || opened.Mode().Perm() != 0700 || !owned(opened) || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, named) {
			return nil, ErrStorage
		}
		// Opening relative to the retained root prevents a later pathname swap from
		// redirecting record staging, lock validation or publication.
		return s.scopedRoot.OpenRoot(".")
	}

	info, err := os.Lstat(s.dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return nil, ErrStorage
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, ErrStorage
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, ErrStorage
	}
	return root, nil
}

func closeRoot(root *os.Root, result *error) {
	if err := root.Close(); err != nil && *result == nil {
		*result = ErrStorage
	}
}

func syncDirectory(root *os.Root, path string) error {
	directory, err := root.Open(path)
	if err != nil {
		return ErrStorage
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStorage
	}
	return nil
}

func writeOwner(root *os.Root, path string, data []byte) error {
	file, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = file.Close() }()
	// An incomplete ownership marker is deliberately preserved for inspection.
	if _, err = file.Write(data); err != nil {
		return ErrStorage
	}
	if err = file.Sync(); err != nil {
		return ErrStorage
	}
	if err = file.Close(); err != nil {
		return ErrStorage
	}
	return nil
}

func readOwner(root *os.Root, path string) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil || !regularOwned(info, maxMarkerBytes) {
		return nil, ErrStorage
	}
	data, err := root.ReadFile(path)
	if err != nil {
		return nil, ErrStorage
	}
	var owner stageOwner
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&owner) != nil || decoder.Decode(new(any)) != io.EOF || owner.Format != "andeiva.config.staging.v1" {
		return nil, ErrStorage
	}
	id, err := hex.DecodeString(owner.StoreID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != owner.StoreID {
		return nil, ErrStorage
	}
	canonical, err := json.Marshal(owner)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrStorage
	}
	return data, nil
}

func (s *fileStore) initializeStaging(root *os.Root) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ErrStorage
	}
	data, err := json.Marshal(stageOwner{Format: "andeiva.config.staging.v1", StoreID: hex.EncodeToString(id[:])})
	if err != nil {
		return ErrStorage
	}
	if err = writeOwner(root, stagingRegistration, data); err != nil {
		return err
	}
	if err = syncDirectory(root, "."); err != nil {
		return err
	}
	stage := stagingDirectory
	if err = root.Mkdir(stage, 0700); err != nil {
		return ErrStorage
	}
	if err = syncDirectory(root, "."); err != nil {
		return err
	}
	if err = writeOwner(root, filepath.Join(stage, stagingMarker), data); err != nil {
		return err
	}
	if err = syncDirectory(root, stage); err != nil {
		return err
	}
	s.owner = append([]byte{}, data...)
	return nil
}

// validateStaging recognizes only the registered, versioned namespace. The marker
// binds an incomplete payload to this store; it does not authenticate against a
// writer using the same UID or root.
func (s *fileStore) validateStaging(root *os.Root) (os.FileInfo, error) {
	registration, err := readOwner(root, stagingRegistration)
	if err != nil {
		return nil, err
	}
	if len(s.owner) > 0 && !bytes.Equal(s.owner, registration) {
		return nil, ErrStorage
	}
	stage := stagingDirectory
	info, err := root.Lstat(stage)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return nil, ErrStorage
	}
	directory, err := root.Open(stage)
	if err != nil {
		return nil, ErrStorage
	}
	entries, readErr := directory.ReadDir(3)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) < 1 || len(entries) > 2 {
		return nil, ErrStorage
	}
	markerFound := false
	var payload os.FileInfo
	for _, entry := range entries {
		switch entry.Name() {
		case stagingMarker:
			marker, err := readOwner(root, filepath.Join(stage, stagingMarker))
			if err != nil || !bytes.Equal(marker, registration) {
				return nil, ErrStorage
			}
			markerFound = true
		case stagingPayload:
			info, err := root.Lstat(filepath.Join(stage, entry.Name()))
			if err != nil || !regularOwned(info, maxRecordBytes) {
				return nil, ErrStorage
			}
			payload = info
		default:
			return nil, ErrStorage
		}
	}
	if !markerFound {
		return nil, ErrStorage
	}
	s.owner = append([]byte{}, registration...)
	return payload, nil
}

func (s *fileStore) removePayload(root *os.Root, expected os.FileInfo) error {
	current, err := s.validateStaging(root)
	if err != nil || current == nil || !os.SameFile(current, expected) {
		return ErrStorage
	}
	if err = root.Remove(filepath.Join(stagingDirectory, stagingPayload)); err != nil {
		return ErrStorage
	}
	return syncDirectory(root, stagingDirectory)
}

func stageHook(hook func(string) error, point string) error {
	if hook != nil {
		return hook(point)
	}
	return nil
}
