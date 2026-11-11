//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

func checkpointFixtureArea(t *testing.T) (*os.Root, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checkpoints")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, path
}

func TestCheckpointPreparationPreservesLiveStateAndLegacyReplay(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	area, path := checkpointFixtureArea(t)
	before := status(t, s)
	config := sample("first")
	request := Request{Operation: OpStage, Key: "retained-key", ExpectedGeneration: before.Generation, Config: &config}
	first, err := s.Execute(context.Background(), admin, Web, request)
	if err != nil {
		t.Fatal(err)
	}
	invoke(t, s, OpValidate, nil, 0)
	invoke(t, s, OpCommit, nil, 0)
	invoke(t, s, OpSave, nil, 0)
	journal := journalFiles(t, dir)
	state := clone(s.state)
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal(err)
	}
	image, err := s.readCheckpoint(area)
	if err != nil || !checkpointEqual(state, image.State) {
		t.Fatal("checkpoint lost a state or receipt", err)
	}
	if !reflect.DeepEqual(journal, journalFiles(t, dir)) || !checkpointEqual(state, s.state) {
		t.Fatal("preparation mutated live state/history")
	}
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal("same sequence must be idempotent", err)
	}
	if _, err := os.Stat(filepath.Join(path, "checkpoint-2.json")); !os.IsNotExist(err) {
		t.Fatal("idempotence consumed a slot")
	}
	image.State.Receipts = nil
	image.State.Snapshot.Running.Config.Rules[0].Action = "deny"
	if !checkpointEqual(state, s.state) {
		t.Fatal("returned image aliases live state")
	}
	invoke(t, s, OpStage, ptrCheckpointConfig(sample("second")), 0)
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal(err)
	}
	latest := clone(s.state)
	image, err = s.readCheckpoint(area)
	if err != nil || !checkpointEqual(latest, image.State) {
		t.Fatal("second state not selected", err)
	}
	var manifest checkpointManifest
	data, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Previous == nil {
		t.Fatal("previous checkpoint not retained", err)
	}
	if _, err := os.Stat(filepath.Join(path, checkpointPreviousName)); err != nil {
		t.Fatal(err)
	}
	invoke(t, s, OpValidate, nil, 0)
	if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
		t.Fatal("third publication accepted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal("separate preparation must not alter v1 reopening", err)
	}
	defer func() { _ = reopened.Close() }()
	replay, err := reopened.Execute(context.Background(), admin, CLI, request)
	if err != nil || replay.ReplayedGeneration != first.Generation || replay.Generation != status(t, reopened).Generation || replay.Candidate.Revision.Config.Rules[0].ID != "second" {
		t.Fatal("legacy current-snapshot replay changed", err)
	}
	for name, data := range journal {
		if !reflect.DeepEqual(data, journalFiles(t, dir)[name]) {
			t.Fatal("protected history changed", name)
		}
	}
}

func ptrCheckpointConfig(value Config) *Config { return &value }

func TestCheckpointPreservesPendingConfirmationAndIntent(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	area, _ := checkpointFixtureArea(t)
	invoke(t, s, OpStage, ptrCheckpointConfig(sample("pending")), 0)
	invoke(t, s, OpValidate, nil, 0)
	invoke(t, s, OpCommit, nil, time.Minute)
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal(err)
	}
	image, err := s.readCheckpoint(area)
	if err != nil || image.State.Snapshot.Pending == nil || !checkpointEqual(s.state, image.State) {
		t.Fatal("pending lifecycle omitted", err)
	}
	// A durable intent must be preserved without declaring an interrupted engine
	// transition complete. Construct it through the existing persistence boundary.
	s.mu.Lock()
	s.state.Intent = &Intent{Previous: clone(s.state.Snapshot.LastGood), Target: clone(s.state.Snapshot.Running)}
	err = s.persist("system", API, "checkpoint-fixture-intent", "intent", true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal(err)
	}
	image, err = s.readCheckpoint(area)
	if err != nil || image.State.Intent == nil || !checkpointEqual(s.state, image.State) {
		t.Fatal("durable intent omitted", err)
	}
}

func TestCheckpointInterruptionKeepsSelectedPairAndJournal(t *testing.T) {
	points := []string{"after_image_create", "after_image_partial_write", "before_image_sync", "after_image_sync", "before_image_publish", "after_image_publish", "before_image_directory_sync", "after_image_directory_sync", "after_previous_manifest_create", "after_previous_manifest_partial_write", "before_previous_manifest_sync", "after_previous_manifest_sync", "before_previous_manifest_directory_sync", "after_previous_manifest_directory_sync", "after_manifest_create", "after_manifest_partial_write", "before_manifest_sync", "after_manifest_sync", "before_manifest_select", "after_manifest_select", "before_selection_directory_sync", "after_selection_directory_sync"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			first, err := s.readCheckpoint(area)
			if err != nil {
				t.Fatal(err)
			}
			invoke(t, s, OpStage, ptrCheckpointConfig(sample("new")), 0)
			journal := journalFiles(t, dir)
			live := clone(s.state)
			hit := false
			err = s.prepareCheckpoint(area, checkpointOptions{hook: func(actual string) error {
				if actual == point {
					hit = true
					return errors.New("interruption")
				}
				return nil
			}})
			if !hit || !errors.Is(err, ErrInterrupted) {
				t.Fatal("fault boundary was not exercised", err)
			}
			selected, err := s.readCheckpoint(area)
			if err != nil {
				t.Fatal("last complete selection unavailable", err)
			}
			if selected.Sequence != first.Sequence && !checkpointEqual(selected.State, live) {
				t.Fatal("partial/unknown selection")
			}
			if !reflect.DeepEqual(journal, journalFiles(t, dir)) || !checkpointEqual(live, s.state) {
				t.Fatal("checkpoint failure affected live journal/state")
			}
			if _, err := os.Stat(filepath.Join(path, "checkpoint-1.json")); err != nil {
				t.Fatal("previous image lost", err)
			}
		})
	}
}

func TestCheckpointBootstrapFaultsKeepLegacyJournalOpenable(t *testing.T) {
	for _, point := range []string{"after_owner_create", "after_owner_partial_write", "before_owner_sync", "after_owner_sync", "before_owner_directory_sync", "after_owner_directory_sync", "after_image_partial_write", "before_manifest_select", "after_manifest_select"} {
		t.Run(point, func(t *testing.T) {
			s, engines, dir := fixture(t, Options{})
			area, _ := checkpointFixtureArea(t)
			before := journalFiles(t, dir)
			err := s.prepareCheckpoint(area, checkpointOptions{hook: func(actual string) error {
				if actual == point {
					return errors.New("fault")
				}
				return nil
			}})
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal("fault not exercised", err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, dir)) {
				t.Fatal("bootstrap changed live journal")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
			if err != nil {
				t.Fatal("checkpoint preparation blocked v1 reopening", err)
			}
			_ = reopened.Close()
		})
	}
}

func TestCheckpointRefusesForeignUnsafeAndUnknownAreaEntries(t *testing.T) {
	for _, variant := range []string{"unknown-name", "file-symlink", "directory", "wrong-mode", "hard-link", "oversized", "area-mode", "source-area", "area-symlink"} {
		t.Run(variant, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			before := journalFiles(t, dir)
			switch variant {
			case "unknown-name":
				if err := os.WriteFile(filepath.Join(path, "foreign.txt"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "file-symlink":
				if err := os.Symlink(filepath.Join(dir, "00000001.json"), filepath.Join(path, "checkpoint-1.json")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(filepath.Join(path, "checkpoint-1.json"), 0700); err != nil {
					t.Fatal(err)
				}
			case "wrong-mode":
				if err := os.WriteFile(filepath.Join(path, checkpointOwnerName), []byte("x"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hard-link":
				if err := os.Link(filepath.Join(dir, "00000001.json"), filepath.Join(path, "checkpoint-1.json")); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				file, err := os.OpenFile(filepath.Join(path, checkpointOwnerName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(checkpointManifestLimit + 1); err != nil {
					t.Fatal(err)
				}
				_ = file.Close()
			case "area-mode":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "source-area":
				var err error
				area, err = os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = area.Close() }()
			case "area-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(path, alias); err != nil {
					t.Fatal(err)
				}
				var err error
				area, err = os.OpenRoot(alias)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = area.Close() }()
			}
			if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
				t.Fatal("unsafe area accepted", err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, dir)) {
				t.Fatal("foreign area handling changed live history")
			}
			if variant == "unknown-name" {
				data, err := os.ReadFile(filepath.Join(path, "foreign.txt"))
				if err != nil || string(data) != "foreign" {
					t.Fatal("foreign file modified", err)
				}
			}
		})
	}
}

func TestCheckpointRejectsTamperingUnknownVersionAndCrossStore(t *testing.T) {
	for _, target := range []string{checkpointOwnerName, checkpointManifestName, "checkpoint-1.json"} {
		for _, variant := range []string{"corrupt", "unknown-version", "duplicate-field"} {
			t.Run(target+"/"+variant, func(t *testing.T) {
				s, _, _ := fixture(t, Options{})
				area, path := checkpointFixtureArea(t)
				if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(path, target))
				if err != nil {
					t.Fatal(err)
				}
				switch variant {
				case "corrupt":
					data[len(data)/2] ^= 1
				case "unknown-version":
					var object map[string]any
					if json.Unmarshal(data, &object) != nil {
						t.Fatal("invalid fixture")
					}
					object["format"] = "andeiva.config.checkpoint-preparation.v99"
					data, _ = json.Marshal(object)
				case "duplicate-field":
					data = append([]byte(`{"format":"duplicate",`), data[1:]...)
				}
				if err := os.WriteFile(filepath.Join(path, target), data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.readCheckpoint(area); !errors.Is(err, ErrStorage) {
					t.Fatal("invalid format/checksum accepted", err)
				}
				if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
					t.Fatal("invalid area automatically repaired", err)
				}
			})
		}
	}
	s, _, _ := fixture(t, Options{})
	other, _, _ := fixture(t, Options{})
	area, _ := checkpointFixtureArea(t)
	if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := other.readCheckpoint(area); !errors.Is(err, ErrStorage) {
		t.Fatal("checkpoint accepted by another source", err)
	}
}

func TestCheckpointRejectsUntrustedReferencesAndPreviousManifest(t *testing.T) {
	for _, variant := range []string{"traversal", "future-sequence", "previous-changed", "state-changed"} {
		t.Run(variant, func(t *testing.T) {
			s, _, _ := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			invoke(t, s, OpStage, ptrCheckpointConfig(sample("second")), 0)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil {
				t.Fatal(err)
			}
			var manifest checkpointManifest
			if json.Unmarshal(data, &manifest) != nil {
				t.Fatal("fixture manifest")
			}
			switch variant {
			case "traversal":
				manifest.Current.Name = "../state/00000001.json"
			case "future-sequence":
				manifest.Current.Sequence = uint64(len(s.store.records) + 1)
			case "previous-changed":
				if err := os.WriteFile(filepath.Join(path, checkpointPreviousName), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "state-changed":
				image, err := s.readCheckpoint(area)
				if err != nil {
					t.Fatal(err)
				}
				image.State.Receipts = map[string]receipt{}
				image.Hash = checkpointImageHash(image)
				data, _ = json.Marshal(image)
				if err := os.WriteFile(filepath.Join(path, manifest.Current.Name), data, 0600); err != nil {
					t.Fatal(err)
				}
				manifest.Current.Hash = image.Hash
			}
			manifest.Hash = checkpointManifestHash(manifest)
			data, _ = json.Marshal(manifest)
			if err := os.WriteFile(filepath.Join(path, checkpointManifestName), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.readCheckpoint(area); !errors.Is(err, ErrStorage) {
				t.Fatal("untrusted reference/state accepted", err)
			}
		})
	}
}

func TestCheckpointSpaceAdmissionAndRecoveryState(t *testing.T) {
	for _, variant := range []string{"bytes", "inodes", "readonly", "probe-error", "source-low-space", "source-read-failed", "halted", "closed", "source-drift"} {
		t.Run(variant, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			space := storageSpace{AvailableBytes: 1 << 30, AvailableInodes: 10000, BlockSize: 4096}
			options := checkpointOptions{spaceProbe: func(*os.File) (storageSpace, error) { return space, nil }}
			switch variant {
			case "bytes":
				space.AvailableBytes = 0
			case "inodes":
				space.AvailableInodes = 0
			case "readonly":
				space.ReadOnly = true
			case "probe-error":
				options.spaceProbe = func(*os.File) (storageSpace, error) { return space, syscall.EDQUOT }
			case "source-low-space":
				s.store.spaceProbe = func(*os.File) (storageSpace, error) { return storageSpace{}, nil }
			case "source-read-failed":
				s.store.readFailed = true
			case "halted":
				s.halted = true
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			case "source-drift":
				if err := os.WriteFile(filepath.Join(dir, "00000001.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.prepareCheckpoint(area, options); !errors.Is(err, ErrStorage) {
				t.Fatal("unqualified admission accepted", err)
			}
			if _, err := os.Stat(filepath.Join(path, checkpointOwnerName)); !os.IsNotExist(err) {
				t.Fatal("refusal wrote checkpoint ownership")
			}
		})
	}
}

func TestCheckpointSerializationAndWorkspaceLock(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	area, _ := checkpointFixtureArea(t)
	locked, err := lockCheckpoint(area)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrLocked) {
		t.Fatal("workspace lock bypassed", err)
	}
	_ = locked.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if _, err := s.readCheckpoint(area); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointRejectsJournalDescriptorBeforeAnyMutation(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := journalFiles(t, dir)
	// Distinct directory descriptors still identify the same inode. No lock or
	// format marker may be created in the live journal by caller error.
	for i := 0; i < 2; i++ {
		area, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
			t.Fatal("live journal area accepted", err)
		}
		if _, err := s.readCheckpoint(area); !errors.Is(err, ErrStorage) {
			t.Fatal("live journal read as checkpoint area", err)
		}
		_ = area.Close()
	}
	after, err := os.ReadDir(dir)
	if err != nil || len(before) != len(after) {
		t.Fatal("directory entries changed", err)
	}
	for i := range before {
		if before[i].Name() != after[i].Name() {
			t.Fatal("new journal entry created")
		}
	}
	if !reflect.DeepEqual(files, journalFiles(t, dir)) {
		t.Fatal("live journal contents changed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal("caller error prevented v1 reopening", err)
	}
	_ = reopened.Close()
}

func TestCheckpointRejectsAreaNestedInLiveJournal(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	before := journalFiles(t, dir)
	path := filepath.Join(dir, "caller-created-area")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
		t.Fatal("nested journal area accepted", err)
	}
	_ = area.Close()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("nested area mutated", err)
	}
	if !reflect.DeepEqual(before, journalFiles(t, dir)) {
		t.Fatal("live journal changed")
	}
	// The test owns this empty invalid directory; the preparation never removes
	// caller files. Remove only this fixture directory before legacy reopening.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

func TestCheckpointRejectsAreaContainingLiveJournal(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	before := journalFiles(t, dir)
	path := filepath.Dir(dir)
	entriesBefore, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareCheckpoint(area, checkpointOptions{}); !errors.Is(err, ErrStorage) {
		t.Fatal("ancestor of live journal accepted", err)
	}
	_ = area.Close()
	entriesAfter, err := os.ReadDir(path)
	if err != nil || len(entriesBefore) != len(entriesAfter) {
		t.Fatal("ancestor area changed", err)
	}
	for i := range entriesBefore {
		if entriesBefore[i].Name() != entriesAfter[i].Name() {
			t.Fatal("ancestor entries changed")
		}
	}
	if !reflect.DeepEqual(before, journalFiles(t, dir)) {
		t.Fatal("live journal changed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

func TestCheckpointMetadataDriftBeforePublicationIsRefused(t *testing.T) {
	for _, variant := range []string{"mode", "link", "replacement"} {
		t.Run(variant, func(t *testing.T) {
			s, _, _ := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			first, err := s.readCheckpoint(area)
			if err != nil {
				t.Fatal(err)
			}
			invoke(t, s, OpStage, ptrCheckpointConfig(sample("next")), 0)
			err = s.prepareCheckpoint(area, checkpointOptions{hook: func(point string) error {
				if point != "after_image_partial_write" {
					return nil
				}
				switch variant {
				case "mode":
					return os.Chmod(filepath.Join(path, checkpointTemporaryName), 0644)
				case "link":
					return os.Link(filepath.Join(path, checkpointTemporaryName), filepath.Join(t.TempDir(), "linked"))
				case "replacement":
					if err := os.Rename(filepath.Join(path, checkpointTemporaryName), filepath.Join(t.TempDir(), "detached")); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(path, checkpointTemporaryName), []byte("{}"), 0600)
				}
				return nil
			}})
			if !errors.Is(err, ErrStorage) {
				t.Fatal("substituted payload was published", err)
			}
			data, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil {
				t.Fatal(err)
			}
			var manifest checkpointManifest
			if json.Unmarshal(data, &manifest) != nil || manifest.Current.Sequence != first.Sequence {
				t.Fatal("previous manifest changed")
			}
		})
	}
}

func TestCheckpointLateImageMutationIsNotPublished(t *testing.T) {
	testCheckpointLateMutation(t, "before_image_publish", checkpointTemporaryName)
}

func TestCheckpointLateManifestMutationIsNotSelected(t *testing.T) {
	testCheckpointLateMutation(t, "before_manifest_select", checkpointSelectionName)
}

func testCheckpointLateMutation(t *testing.T, point, target string) {
	t.Helper()
	for _, variant := range []string{"bytes", "mode", "symlink", "replacement", "replacement-identical", "hard-link"} {
		t.Run(variant, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			selectedBefore, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil {
				t.Fatal(err)
			}
			imageBefore, err := os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
			if err != nil {
				t.Fatal(err)
			}
			invoke(t, s, OpStage, ptrCheckpointConfig(sample("late-change")), 0)
			journalBefore := journalFiles(t, dir)
			hit := false
			err = s.prepareCheckpoint(area, checkpointOptions{hook: func(actual string) error {
				if actual != point {
					return nil
				}
				hit = true
				name := filepath.Join(path, target)
				switch variant {
				case "bytes":
					return os.WriteFile(name, []byte("{}"), 0600)
				case "mode":
					return os.Chmod(name, 0644)
				case "symlink":
					if err := os.Remove(name); err != nil {
						return err
					}
					return os.Symlink(filepath.Join(path, "checkpoint-1.json"), name)
				case "replacement":
					if err := os.Rename(name, filepath.Join(t.TempDir(), "original")); err != nil {
						return err
					}
					return os.WriteFile(name, []byte("{}"), 0600)
				case "replacement-identical":
					original, err := os.ReadFile(name)
					if err != nil {
						return err
					}
					originalInfo, err := os.Stat(name)
					if err != nil {
						return err
					}
					if err := os.Rename(name, filepath.Join(t.TempDir(), "original")); err != nil {
						return err
					}
					if err := os.WriteFile(name, original, 0600); err != nil {
						return err
					}
					// Match timestamp and bytes deliberately: the inode witness,
					// not content equality alone, must refuse this replacement.
					if err := os.Chtimes(name, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
						return err
					}
					replacementInfo, err := os.Stat(name)
					if err != nil {
						return err
					}
					if os.SameFile(originalInfo, replacementInfo) {
						return errors.New("fixture did not replace inode")
					}
					return nil
				case "hard-link":
					return os.Link(name, filepath.Join(t.TempDir(), "linked"))
				}
				return nil
			}})
			if !hit || !errors.Is(err, ErrStorage) {
				t.Fatal("late mutation was not refused before selection", err)
			}
			selectedAfter, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil {
				t.Fatal(err)
			}
			imageAfter, err := os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(selectedBefore, selectedAfter) || !reflect.DeepEqual(imageBefore, imageAfter) {
				t.Fatal("previous complete selection changed")
			}
			if !reflect.DeepEqual(journalBefore, journalFiles(t, dir)) {
				t.Fatal("late cache mutation changed protected journal")
			}
		})
	}
}

func TestCheckpointCrashChild(t *testing.T) {
	if os.Getenv("ANDEIVA_CHECKPOINT_CHILD") != "1" {
		return
	}
	s, err := Open(os.Getenv("ANDEIVA_CHECKPOINT_JOURNAL"), []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	current := status(t, s)
	config := sample("after-restart")
	if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStage, Key: "child-stage", ExpectedGeneration: current.Generation, Config: &config}); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(os.Getenv("ANDEIVA_CHECKPOINT_AREA"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = area.Close() }()
	point := os.Getenv("ANDEIVA_CHECKPOINT_POINT")
	_ = s.prepareCheckpoint(area, checkpointOptions{hook: func(actual string) error {
		if actual == point {
			os.Exit(73)
		}
		return nil
	}})
	t.Fatal("crash boundary was not reached")
}

func TestCheckpointActualProcessExitAndReopen(t *testing.T) {
	for _, point := range []string{"after_image_partial_write", "after_image_publish", "before_manifest_select", "after_manifest_select"} {
		t.Run(point, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, dir)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestCheckpointCrashChild$")
			command.Env = append(os.Environ(), "ANDEIVA_CHECKPOINT_CHILD=1", "ANDEIVA_CHECKPOINT_JOURNAL="+dir, "ANDEIVA_CHECKPOINT_AREA="+path, "ANDEIVA_CHECKPOINT_POINT="+point)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("unexpected child exit: %v %s", err, output)
			}
			reopened, err := Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			if _, err := reopened.readCheckpoint(area); err != nil {
				t.Fatal("complete selected checkpoint not readable after process exit", err)
			}
			for name, data := range before {
				if !reflect.DeepEqual(data, journalFiles(t, dir)[name]) {
					t.Fatal("crash altered protected history", name)
				}
			}
			if status(t, reopened).Candidate == nil || status(t, reopened).Candidate.Revision.Config.Rules[0].ID != "after-restart" {
				t.Fatal("checkpoint cache replaced authoritative live state")
			}
		})
	}
}

func BenchmarkCheckpointPreparation(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		base := b.TempDir()
		dir := filepath.Join(base, "state")
		areaPath := filepath.Join(base, "checkpoints")
		if err := os.Mkdir(areaPath, 0700); err != nil {
			b.Fatal(err)
		}
		s, err := Open(dir, []Engine{NewSimEngine("first")}, Options{})
		if err != nil {
			b.Fatal(err)
		}
		area, err := os.OpenRoot(areaPath)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		err = s.prepareCheckpoint(area, checkpointOptions{})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		entries, err := os.ReadDir(areaPath)
		if err != nil {
			b.Fatal(err)
		}
		var size int64
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				b.Fatal(err)
			}
			size += info.Size()
		}
		b.ReportMetric(float64(size), "checkpoint-bytes")
		if err := s.Close(); err != nil {
			b.Fatal(err)
		}
		if err := area.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
