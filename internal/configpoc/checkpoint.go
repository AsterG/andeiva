package configpoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	checkpointFormat        = "andeiva.config.checkpoint-preparation.v1"
	checkpointOwnerName     = "checkpoint.owner"
	checkpointManifestName  = "manifest.json"
	checkpointPreviousName  = "manifest.previous.json"
	checkpointTemporaryName = "checkpoint.pending"
	checkpointSelectionName = "manifest.pending"
	checkpointManifestLimit = 4096
)

type checkpointOptions struct {
	hook       func(string) error
	spaceProbe func(*os.File) (storageSpace, error)
}

type checkpointOwner struct {
	Format string `json:"format"`
	Source string `json:"source"`
}

type checkpointReference struct {
	Name        string `json:"name"`
	Sequence    uint64 `json:"sequence"`
	Generation  uint64 `json:"generation"`
	JournalHash string `json:"journal_hash"`
	Hash        string `json:"hash"`
}

type checkpointManifest struct {
	Format   string               `json:"format"`
	Source   string               `json:"source"`
	Current  checkpointReference  `json:"current"`
	Previous *checkpointReference `json:"previous,omitempty"`
	Hash     string               `json:"hash"`
}

type checkpointImage struct {
	Format      string       `json:"format"`
	Source      string       `json:"source"`
	Sequence    uint64       `json:"sequence"`
	JournalHash string       `json:"journal_hash"`
	State       durableState `json:"state"`
	Hash        string       `json:"hash"`
}

// prepareCheckpoint is an unconnected storage preparation, not a migration or a
// new administrative operation. The caller supplies a private, separate area;
// neither the live journal nor protected history is replaced or deleted.
func (s *Service) prepareCheckpoint(area *os.Root, options checkpointOptions) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.halted || s.store == nil || s.store.readFailed || len(s.store.records) == 0 {
		return ErrStorage
	}
	if err := s.checkCheckpointArea(area); err != nil {
		return err
	}
	lock, err := lockCheckpoint(area)
	if err != nil {
		return err
	}
	defer func() {
		if lock.Close() != nil {
			result = ErrStorage
		}
	}()
	entries, err := checkpointEntries(area)
	if err != nil {
		return err
	}
	if entries[checkpointTemporaryName] || entries[checkpointSelectionName] {
		return ErrStorage
	}
	source, err := s.checkpointSource()
	if err != nil {
		return err
	}
	sequence := uint64(len(s.store.records))
	var record journalRecord
	// Revalidate protected history without retaining its historical states. A
	// checkpoint must not hide changed or missing records behind its latest tip.
	for i := uint64(1); i <= sequence; i++ {
		record, err = s.store.read(i)
		if err != nil {
			return err
		}
	}
	if !checkpointEqual(s.state, record.State) {
		return ErrStorage
	}
	var previous *checkpointManifest
	if entries[checkpointOwnerName] {
		if err := verifyCheckpointOwner(area, source); err != nil {
			return err
		}
		if entries[checkpointManifestName] {
			manifest, _, err := s.readCheckpointLocked(area, source)
			if err != nil {
				return err
			}
			if manifest.Current.Sequence == sequence {
				return nil
			}
			if manifest.Current.Name == "checkpoint-2.json" {
				return ErrStorage
			}
			previous = &manifest
		} else if len(entries) != 2 {
			return ErrStorage
		}
	} else if len(entries) != 1 {
		return ErrStorage
	}
	if !checkpointSpace(area, options.spaceProbe) || !s.store.spaceCapacity(2) {
		return ErrStorage
	}
	if !entries[checkpointOwnerName] {
		data, _ := json.Marshal(checkpointOwner{Format: checkpointFormat, Source: source})
		if _, err := checkpointWrite(area, checkpointOwnerName, data, options.hook, "owner"); err != nil {
			return err
		}
		if err := checkpointSync(area, options.hook, "owner"); err != nil {
			return err
		}
	}
	image := checkpointImage{Format: checkpointFormat, Source: source, Sequence: sequence, JournalHash: record.Hash, State: clone(record.State)}
	image.Hash = checkpointImageHash(image)
	data, err := json.Marshal(image)
	if err != nil || len(data) > maxRecordBytes {
		return ErrStorage
	}
	name := "checkpoint-1.json"
	if previous != nil {
		name = "checkpoint-2.json"
	}
	if entries[name] {
		return ErrStorage
	}
	syncedImage, err := checkpointWrite(area, checkpointTemporaryName, data, options.hook, "image")
	if err != nil {
		return err
	}
	if err := checkpointPoint(options.hook, "before_image_publish"); err != nil {
		return err
	}
	verifiedImage, err := checkpointReadPinned(area, checkpointTemporaryName, maxRecordBytes, syncedImage)
	if err != nil || !bytes.Equal(verifiedImage, data) {
		return ErrStorage
	}
	if _, err := area.Lstat(name); !os.IsNotExist(err) {
		return ErrStorage
	}
	if err := checkpointPoint(options.hook, "after_image_destination_check"); err != nil {
		return err
	}
	if err := publishCheckpointImage(area, name); err != nil {
		return ErrStorage
	}
	if err := checkpointPoint(options.hook, "after_image_publish"); err != nil {
		return err
	}
	if err := checkpointSync(area, options.hook, "image"); err != nil {
		return err
	}
	manifest := checkpointManifest{Format: checkpointFormat, Source: source, Current: checkpointReference{Name: name, Sequence: sequence, Generation: record.State.Snapshot.Generation, JournalHash: record.Hash, Hash: image.Hash}}
	if previous != nil {
		manifest.Previous = &previous.Current
		old, _ := json.Marshal(previous)
		if _, err := checkpointWrite(area, checkpointPreviousName, old, options.hook, "previous_manifest"); err != nil {
			return err
		}
		if err := checkpointSync(area, options.hook, "previous_manifest"); err != nil {
			return err
		}
	}
	manifest.Hash = checkpointManifestHash(manifest)
	data, _ = json.Marshal(manifest)
	syncedManifest, err := checkpointWrite(area, checkpointSelectionName, data, options.hook, "manifest")
	if err != nil {
		return err
	}
	if err := checkpointPoint(options.hook, "before_manifest_select"); err != nil {
		return err
	}
	verifiedManifest, err := checkpointReadPinned(area, checkpointSelectionName, checkpointManifestLimit, syncedManifest)
	if err != nil || !bytes.Equal(verifiedManifest, data) {
		return ErrStorage
	}
	if err := area.Rename(checkpointSelectionName, checkpointManifestName); err != nil {
		return ErrStorage
	}
	if err := checkpointPoint(options.hook, "after_manifest_select"); err != nil {
		return err
	}
	if err := checkpointSync(area, options.hook, "selection"); err != nil {
		return err
	}
	_, _, err = s.readCheckpointLocked(area, source)
	return err
}

// readCheckpoint validates the selected image against the authoritative live v1
// journal. It never installs that image into Service.state or applies an engine.
func (s *Service) readCheckpoint(area *os.Root) (image checkpointImage, result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.halted || s.store == nil || s.store.readFailed {
		return image, ErrStorage
	}
	if err := s.checkCheckpointArea(area); err != nil {
		return image, err
	}
	lock, err := lockCheckpoint(area)
	if err != nil {
		return image, err
	}
	defer func() {
		if lock.Close() != nil {
			result = ErrStorage
		}
	}()
	if _, err := checkpointEntries(area); err != nil {
		return image, err
	}
	source, err := s.checkpointSource()
	if err != nil {
		return image, err
	}
	if err := verifyCheckpointOwner(area, source); err != nil {
		return image, err
	}
	_, image, result = s.readCheckpointLocked(area, source)
	return image, result
}

func (s *Service) checkpointSource() (string, error) {
	root, err := s.store.openScopedRoot()
	if err != nil {
		return "", err
	}
	payload, err := s.store.validateStaging(root)
	closeErr := root.Close()
	if err != nil || payload != nil || closeErr != nil || len(s.store.owner) == 0 {
		return "", ErrStorage
	}
	return checkpointDigest(s.store.owner), nil
}

func (s *Service) readCheckpointLocked(area *os.Root, source string) (manifest checkpointManifest, image checkpointImage, err error) {
	data, err := checkpointRead(area, checkpointManifestName, checkpointManifestLimit)
	if err != nil || checkpointDecode(data, &manifest) != nil || manifest.Format != checkpointFormat || manifest.Source != source || manifest.Hash != checkpointManifestHash(manifest) {
		return manifest, image, ErrStorage
	}
	image, err = s.checkpointImage(area, manifest.Current, source)
	if err != nil {
		return manifest, image, err
	}
	if manifest.Current.Name == "checkpoint-1.json" {
		if manifest.Previous != nil {
			return manifest, image, ErrStorage
		}
	} else if manifest.Current.Name == "checkpoint-2.json" {
		if manifest.Previous == nil || manifest.Previous.Name != "checkpoint-1.json" || manifest.Previous.Sequence >= manifest.Current.Sequence {
			return manifest, image, ErrStorage
		}
		if _, err := s.checkpointImage(area, *manifest.Previous, source); err != nil {
			return manifest, image, err
		}
		var old checkpointManifest
		data, err := checkpointRead(area, checkpointPreviousName, checkpointManifestLimit)
		if err != nil || checkpointDecode(data, &old) != nil || old.Format != checkpointFormat || old.Source != source || old.Hash != checkpointManifestHash(old) || old.Previous != nil || old.Current != *manifest.Previous {
			return manifest, image, ErrStorage
		}
	} else {
		return manifest, image, ErrStorage
	}
	return manifest, image, nil
}

func (s *Service) checkpointImage(area *os.Root, ref checkpointReference, source string) (image checkpointImage, err error) {
	if (ref.Name != "checkpoint-1.json" && ref.Name != "checkpoint-2.json") || ref.Sequence == 0 || ref.Sequence > uint64(len(s.store.records)) || !validHash(ref.Hash) || !validHash(ref.JournalHash) {
		return image, ErrStorage
	}
	data, err := checkpointRead(area, ref.Name, maxRecordBytes)
	if err != nil || checkpointDecode(data, &image) != nil || image.Format != checkpointFormat || image.Source != source || image.Hash != checkpointImageHash(image) || image.Hash != ref.Hash || image.JournalHash != ref.JournalHash || image.Sequence != ref.Sequence || image.State.Snapshot.Generation != ref.Generation || !validState(image.State) {
		return image, ErrStorage
	}
	record, err := s.store.read(ref.Sequence)
	if err != nil || record.Hash != image.JournalHash || !checkpointEqual(record.State, image.State) {
		return image, ErrStorage
	}
	return image, nil
}

func (s *Service) checkCheckpointArea(area *os.Root) error {
	if area == nil {
		return ErrStorage
	}
	path := area.Name()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrStorage
	}
	for part := path; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrStorage
		}
		if part == filepath.Dir(part) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return ErrStorage
	}
	opened, err := area.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return ErrStorage
	}
	source, err := s.store.openScopedRoot()
	if err != nil {
		return err
	}
	sourceInfo, statErr := source.Stat(".")
	closeErr := source.Close()
	if statErr != nil || closeErr != nil || os.SameFile(opened, sourceInfo) {
		return ErrStorage
	}
	// A caller-created child of the live journal is not an independent area.
	// Compare ancestor identities as well as names before creating a lock file.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || os.SameFile(info, sourceInfo) {
			return ErrStorage
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	for parent := filepath.Dir(s.store.dir); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || os.SameFile(info, opened) {
			return ErrStorage
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	_, err = checkpointEntries(area)
	return err
}

func checkpointEntries(area *os.Root) (map[string]bool, error) {
	file, err := area.Open(".")
	if err != nil {
		return nil, ErrStorage
	}
	entries, readErr := file.ReadDir(9)
	closeErr := file.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > 8 {
		return nil, ErrStorage
	}
	result := make(map[string]bool, len(entries))
	for _, entry := range entries {
		limit := int64(maxRecordBytes)
		switch entry.Name() {
		case "checkpoint.lock":
			limit = 0
		case checkpointOwnerName, checkpointManifestName, checkpointPreviousName, checkpointSelectionName:
			limit = checkpointManifestLimit
		case "checkpoint-1.json", "checkpoint-2.json", checkpointTemporaryName:
		default:
			return nil, ErrStorage
		}
		info, err := area.Lstat(entry.Name())
		if err != nil || !regularOwned(info, limit) {
			return nil, ErrStorage
		}
		result[entry.Name()] = true
	}
	return result, nil
}

func verifyCheckpointOwner(area *os.Root, source string) error {
	data, err := checkpointRead(area, checkpointOwnerName, checkpointManifestLimit)
	var owner checkpointOwner
	if err != nil || checkpointDecode(data, &owner) != nil || owner.Format != checkpointFormat || owner.Source != source {
		return ErrStorage
	}
	return nil
}

func checkpointSpace(area *os.Root, probe func(*os.File) (storageSpace, error)) bool {
	file, err := area.Open(".")
	if err != nil {
		return false
	}
	if probe == nil {
		probe = probeStorageSpace
	}
	space, err := probe(file)
	closeErr := file.Close()
	// Observed headroom covers both images, staging and three recovery records.
	// This neither allocates storage nor isolates it from other writers.
	return err == nil && closeErr == nil && space.admits(5)
}

func checkpointWrite(area *os.Root, name string, data []byte, hook func(string) error, label string) (synced os.FileInfo, result error) {
	file, err := area.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if file.Close() != nil && result == nil {
			result = ErrStorage
		}
	}()
	created, err := file.Stat()
	if err != nil || !regularOwned(created, 0) {
		return nil, ErrStorage
	}
	if err := checkpointPoint(hook, "after_"+label+"_create"); err != nil {
		return nil, err
	}
	middle := len(data) / 2
	if n, err := file.Write(data[:middle]); err != nil || n != middle {
		return nil, ErrStorage
	}
	if err := checkpointPoint(hook, "after_"+label+"_partial_write"); err != nil {
		return nil, err
	}
	if n, err := file.Write(data[middle:]); err != nil || n != len(data)-middle {
		return nil, ErrStorage
	}
	completed, err := file.Stat()
	if err != nil || !regularOwned(completed, int64(len(data))) || completed.Size() != int64(len(data)) || !os.SameFile(created, completed) {
		return nil, ErrStorage
	}
	named, err := area.Lstat(name)
	if err != nil || !sameRecordFile(completed, named) {
		return nil, ErrStorage
	}
	if err := checkpointPoint(hook, "before_"+label+"_sync"); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, ErrStorage
	}
	// Capture the descriptor that was synchronized, not a replacement found at
	// the same path later. Identical bytes on an unsynchronized inode do not
	// inherit the original inode's durability.
	synced, err = file.Stat()
	if err != nil || !sameRecordFile(completed, synced) {
		return nil, ErrStorage
	}
	if err := checkpointPoint(hook, "after_"+label+"_sync"); err != nil {
		return nil, err
	}
	return synced, nil
}

func checkpointSync(area *os.Root, hook func(string) error, label string) error {
	if err := checkpointPoint(hook, "before_"+label+"_directory_sync"); err != nil {
		return err
	}
	if err := syncDirectory(area, "."); err != nil {
		return err
	}
	return checkpointPoint(hook, "after_"+label+"_directory_sync")
}

func checkpointPoint(hook func(string) error, point string) error {
	if hook != nil && hook(point) != nil {
		return ErrInterrupted
	}
	return nil
}

func checkpointRead(area *os.Root, name string, limit int64) (data []byte, result error) {
	return checkpointReadPinned(area, name, limit, nil)
}

func checkpointReadPinned(area *os.Root, name string, limit int64, expected os.FileInfo) (data []byte, result error) {
	before, err := area.Lstat(name)
	if err != nil || !regularOwned(before, limit) || (expected != nil && !sameRecordFile(expected, before)) {
		return nil, ErrStorage
	}
	file, err := openRecordFile(area, name)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if file.Close() != nil {
			result = ErrStorage
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameRecordFile(before, opened) {
		return nil, ErrStorage
	}
	data = make([]byte, int(opened.Size())+1)
	n, err := io.ReadFull(file, data)
	if err != io.ErrUnexpectedEOF || int64(n) != opened.Size() {
		return nil, ErrStorage
	}
	after, err := file.Stat()
	if err != nil || !sameRecordFile(opened, after) {
		return nil, ErrStorage
	}
	current, err := area.Lstat(name)
	if err != nil || !sameRecordFile(after, current) {
		return nil, ErrStorage
	}
	return data[:n], nil
}

func checkpointDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrStorage
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrStorage
	}
	return nil
}

func checkpointDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func checkpointImageHash(value checkpointImage) string {
	value.Hash = ""
	data, _ := json.Marshal(value)
	return checkpointDigest(data)
}
func checkpointManifestHash(value checkpointManifest) string {
	value.Hash = ""
	data, _ := json.Marshal(value)
	return checkpointDigest(data)
}
func checkpointEqual(a, b durableState) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
