//go:build linux

package storagevol

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const fixtureID = "0123456789abcdef0123456789abcdef"

func fixture(t testing.TB) (*os.Root, string, preparationOptions) {
	t.Helper()
	path := t.TempDir()
	if os.Chmod(path, 0700) != nil {
		t.Fatal("chmod")
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = area.Close() })
	o := defaults()
	o.uid = uint32(os.Geteuid())
	o.gid = uint32(os.Getegid())
	o.space = func(*os.Root, uint64) error { return nil }
	o.format = fakeFormat
	for i := range o.plans {
		o.plans[i].Bytes = 4 * mib
		o.plans[i].Inodes = 128
	}
	return area, path, o
}

// A minimal signature fixture exercises the reader and I/O boundaries. It is not
// an ext4 formatter or evidence that these test images can be mounted.
func fakeFormat(_ context.Context, file *os.File, p VolumePlan) error {
	var data [1024]byte
	binary.LittleEndian.PutUint32(data[0:], p.Inodes)
	binary.LittleEndian.PutUint32(data[4:], uint32(p.Bytes/4096))
	binary.LittleEndian.PutUint32(data[0x18:], 2)
	binary.LittleEndian.PutUint16(data[0x38:], 0xef53)
	binary.LittleEndian.PutUint32(data[0x5c:], 4)
	copy(data[0x68:0x78], []byte(p.Domain+"-fixture"))
	_, err := file.WriteAt(data[:], 1024)
	return err
}

func TestPreparedImagesRoundTripAndBoundedAllocation(t *testing.T) {
	area, path, o := fixture(t)
	value, err := prepareIn(context.Background(), area, fixtureID, o)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := inspectIn(context.Background(), area, fixtureID, o)
	if err != nil || !reflect.DeepEqual(actual, value) {
		t.Fatal("round trip", err)
	}
	if value.State != "inactive_preparation" || value.TotalBytes != 16*mib || len(value.Volumes) != 4 {
		t.Fatal("incorrect profile")
	}
	for _, v := range value.Volumes {
		info, err := os.Lstat(filepath.Join(path, v.File))
		if err != nil || !allocated(info, v.VolumePlan, o) || v.AllocatedBytes < v.Bytes {
			t.Fatal("unallocated image", err)
		}
	}
	if _, err = prepareIn(context.Background(), area, fixtureID, o); !errors.Is(err, ErrExists) {
		t.Fatal("preparation reused an existing workspace", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, e := inspectIn(context.Background(), area, fixtureID, o)
			if e != nil || !reflect.DeepEqual(snapshot, value) {
				t.Error("concurrent read", e)
			}
		}()
	}
	wg.Wait()
}

func TestAllocationFailureAndSparseFallbackAreRefused(t *testing.T) {
	for _, mode := range []string{"unsupported", "sparse", "space"} {
		t.Run(mode, func(t *testing.T) {
			area, path, o := fixture(t)
			formatted := false
			o.format = func(context.Context, *os.File, VolumePlan) error { formatted = true; return nil }
			switch mode {
			case "unsupported":
				o.allocate = func(*os.File, uint64) error { return unix.EOPNOTSUPP }
			case "sparse":
				o.allocate = func(file *os.File, n uint64) error { return file.Truncate(int64(n)) }
			case "space":
				o.space = func(*os.Root, uint64) error { return ErrCapacity }
			}
			if _, err := prepareIn(context.Background(), area, fixtureID, o); err == nil || formatted {
				t.Fatal("allocation failed open", err)
			}
			if _, err := os.Lstat(filepath.Join(path, manifestName)); !os.IsNotExist(err) {
				t.Fatal("failure selected a manifest")
			}
		})
	}
}

func TestPublicationDoesNotReplaceCompetingManifest(t *testing.T) {
	area, path, o := fixture(t)
	foreign := []byte("foreign manifest")
	var info os.FileInfo
	o.point = func(name string) error {
		if name == "before_manifest_publish" {
			if err := os.WriteFile(filepath.Join(path, manifestName), foreign, 0600); err != nil {
				return err
			}
			var err error
			info, err = os.Lstat(filepath.Join(path, manifestName))
			return err
		}
		return nil
	}
	if _, err := prepareIn(context.Background(), area, fixtureID, o); err == nil {
		t.Fatal("competing manifest was replaced")
	}
	after, err := os.Lstat(filepath.Join(path, manifestName))
	if err != nil || !os.SameFile(info, after) {
		t.Fatal("foreign inode changed", err)
	}
	data, err := os.ReadFile(filepath.Join(path, manifestName))
	if err != nil || !bytes.Equal(data, foreign) {
		t.Fatal("foreign content changed", err)
	}
	if _, err = os.Lstat(filepath.Join(path, pendingName)); err != nil {
		t.Fatal("own staging removed after collision", err)
	}
}

func TestInterruptedPreparationRetainsArtifactsWithoutActivation(t *testing.T) {
	for _, fault := range []string{"before_allocate:config", "before_format:audit", "after_format:observations", "before_manifest_publish", "after_manifest_publish"} {
		t.Run(fault, func(t *testing.T) {
			area, path, o := fixture(t)
			hit := false
			o.point = func(name string) error {
				if name == fault {
					hit = true
					return ErrStorage
				}
				return nil
			}
			value, err := prepareIn(context.Background(), area, fixtureID, o)
			if err == nil || !hit || value.ID != fixtureID {
				t.Fatal("fault not reported", err)
			}
			if fault == "after_manifest_publish" {
				if !errors.Is(err, ErrUncertain) {
					t.Fatal("publication ambiguity hidden", err)
				}
				if _, e := inspectIn(context.Background(), area, fixtureID, o); e != nil {
					t.Fatal("retained complete preparation unreadable", e)
				}
			} else if _, e := os.Lstat(filepath.Join(path, manifestName)); !os.IsNotExist(e) {
				t.Fatal("incomplete preparation selected")
			}
			if _, e := prepareIn(context.Background(), area, fixtureID, o); !errors.Is(e, ErrExists) {
				t.Fatal("partial workspace silently reused", e)
			}
		})
	}
}

func TestChangedImageIsNotDeletedOrFollowed(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "mode"} {
		t.Run(kind, func(t *testing.T) {
			area, path, o := fixture(t)
			foreignPath := filepath.Join(t.TempDir(), "unrelated")
			foreign := []byte("unrelated data")
			if os.WriteFile(foreignPath, foreign, 0600) != nil {
				t.Fatal("foreign write")
			}
			image := filepath.Join(path, "config.img")
			o.point = func(name string) error {
				if name != "after_format:config" {
					return nil
				}
				if kind == "mode" {
					return os.Chmod(image, 0640)
				}
				if err := os.Rename(image, filepath.Join(path, "original.img")); err != nil {
					return err
				}
				if kind == "symlink" {
					return os.Symlink(foreignPath, image)
				}
				return os.WriteFile(image, foreign, 0600)
			}
			if _, err := prepareIn(context.Background(), area, fixtureID, o); err == nil {
				t.Fatal("replacement accepted")
			}
			if _, err := os.Lstat(image); err != nil {
				t.Fatal("replacement removed", err)
			}
			data, err := os.ReadFile(foreignPath)
			if err != nil || !bytes.Equal(data, foreign) {
				t.Fatal("unrelated data modified", err)
			}
		})
	}
}

func TestManifestCorruptionAndUnexpectedEntriesAreRefused(t *testing.T) {
	for _, mode := range []string{"hash", "version", "duplicate", "unknown", "whitespace", "oversized", "unexpected", "image-hardlink", "image-fifo", "image-mode"} {
		t.Run(mode, func(t *testing.T) {
			area, path, o := fixture(t)
			if _, err := prepareIn(context.Background(), area, fixtureID, o); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(path, manifestName)
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "hash", "version":
				var v Manifest
				if json.Unmarshal(data, &v) != nil {
					t.Fatal("decode")
				}
				if mode == "hash" {
					v.Hash = strings.Repeat("a", 64)
				} else {
					v.Format = "future-format"
				}
				data, _ = json.Marshal(v)
			case "duplicate":
				data = append([]byte(`{"format":"duplicate",`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"unknown":true,`), data[1:]...)
			case "whitespace":
				data = append(data, '\n')
			case "oversized":
				data = bytes.Repeat([]byte(" "), maxManifestBytes+1)
			case "unexpected":
				if os.WriteFile(filepath.Join(path, "unrecognized"), []byte("retained"), 0600) != nil {
					t.Fatal("write")
				}
			case "image-hardlink":
				if os.Link(filepath.Join(path, "config.img"), filepath.Join(t.TempDir(), "hardlink")) != nil {
					t.Fatal("link")
				}
			case "image-fifo":
				if os.Remove(filepath.Join(path, "config.img")) != nil || unix.Mkfifo(filepath.Join(path, "config.img"), 0600) != nil {
					t.Fatal("fifo")
				}
			case "image-mode":
				if os.Chmod(filepath.Join(path, "config.img"), 0644) != nil {
					t.Fatal("chmod")
				}
			}
			if os.WriteFile(manifest, data, 0600) != nil {
				t.Fatal("manifest write")
			}
			if _, err = inspectIn(context.Background(), area, fixtureID, o); err == nil {
				t.Fatal("unsafe preparation accepted")
			}
			if _, err = os.Lstat(manifest); err != nil {
				t.Fatal("unsafe manifest was deleted", err)
			}
		})
	}
}

func TestInvalidIdentifiersProfilesAndDirectoryPermissionsFailBeforeWrites(t *testing.T) {
	for _, id := range []string{"", "../escape", strings.ToUpper(fixtureID), strings.Repeat("f", 33)} {
		t.Run(id, func(t *testing.T) {
			area, path, o := fixture(t)
			if _, err := prepareIn(context.Background(), area, id, o); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(path)
			if len(entries) != 0 {
				t.Fatal("invalid ID created files")
			}
		})
	}
	area, path, o := fixture(t)
	o.plans[0].File = "../../outside"
	if _, err := prepareIn(context.Background(), area, fixtureID, o); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	o = defaults()
	o.uid = uint32(os.Geteuid())
	o.gid = uint32(os.Getegid())
	if os.Chmod(path, 0755) != nil {
		t.Fatal("chmod")
	}
	if _, err := prepareIn(context.Background(), area, fixtureID, o); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), "../escape"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := Prepare(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestCanceledPreparationRefusesFormatting(t *testing.T) {
	area, _, o := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	o.format = func(context.Context, *os.File, VolumePlan) error { called = true; return nil }
	if _, err := prepareIn(ctx, area, fixtureID, o); err == nil || called {
		t.Fatal("canceled preparation proceeded", err)
	}
}

func BenchmarkInactivePreparation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		area, path, o := fixture(b)
		if _, err := prepareIn(context.Background(), area, fixtureID, o); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = area.Close()
		for _, p := range o.plans {
			if err := os.Remove(filepath.Join(path, p.File)); err != nil {
				b.Fatal(err)
			}
		}
		if err := os.Remove(filepath.Join(path, manifestName)); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func TestAreaCannotBeASymlinkOrArbitraryChild(t *testing.T) {
	base, path, o := fixture(t)
	outside := t.TempDir()
	if os.Symlink(outside, filepath.Join(path, "volumes-"+fixtureID)) != nil {
		t.Fatal("symlink")
	}
	if _, err := openArea(base, "volumes-"+fixtureID, o.uid, o.gid); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink followed", err)
	}
	if _, err := openArea(base, "../escape", o.uid, o.gid); !errors.Is(err, ErrInvalid) {
		t.Fatal("arbitrary path accepted", err)
	}
	info, err := os.Stat(outside)
	if err != nil || !info.IsDir() {
		t.Fatal("outside directory changed")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("outside directory written")
	}
}

func TestFormatterOnlyTargetsInheritedImageFD(t *testing.T) {
	for _, p := range LabPlan().Volumes {
		args, err := formatterArguments(p)
		if err != nil {
			t.Fatal(err)
		}
		if args[len(args)-1] != "/proc/self/fd/3" || strings.Join(args, " ") == "" || strings.Count(strings.Join(args, " "), "-F") != 1 {
			t.Fatal("unsafe target or force flags")
		}
		if len(formatterLabel(p.Domain)) > 16 {
			t.Fatal("truncated filesystem label")
		}
	}
	for _, p := range []VolumePlan{{Domain: "../../escape"}, {Domain: "config", File: "/dev/sda", Bytes: 128 * mib, Inodes: 8192}, {Domain: "config", File: "config.img", Bytes: 129 * mib, Inodes: 8192}} {
		if _, err := formatterArguments(p); !errors.Is(err, ErrInvalid) {
			t.Fatal("untrusted formatter plan accepted", err)
		}
	}
}

func TestPreexistingWorkspaceRetainsUnrelatedFile(t *testing.T) {
	area, path, o := fixture(t)
	file := filepath.Join(path, "keep.txt")
	payload := []byte("foreign data retained")
	if os.WriteFile(file, payload, 0600) != nil {
		t.Fatal("write")
	}
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	o.allocate = func(*os.File, uint64) error { called = true; return nil }
	if _, err = prepareIn(context.Background(), area, fixtureID, o); !errors.Is(err, ErrExists) || called {
		t.Fatal("preexisting workspace touched", err)
	}
	after, err := os.Lstat(file)
	if err != nil || !sameFile(before, after) {
		t.Fatal("foreign identity changed", err)
	}
	data, _ := os.ReadFile(file)
	if !bytes.Equal(data, payload) {
		t.Fatal("foreign bytes changed")
	}
}

func TestStorageVolumeProcessInterruption(t *testing.T) {
	if point := os.Getenv("ANDEIVA_STORAGE_VOLUME_CHILD"); point != "" {
		area, err := os.OpenRoot(os.Getenv("ANDEIVA_STORAGE_VOLUME_FIXTURE"))
		if err != nil {
			t.Fatal(err)
		}
		defer area.Close()
		o := defaults()
		o.uid = uint32(os.Geteuid())
		o.gid = uint32(os.Getegid())
		o.space = func(*os.Root, uint64) error { return nil }
		o.format = fakeFormat
		for i := range o.plans {
			o.plans[i].Bytes = 4 * mib
			o.plans[i].Inodes = 128
		}
		o.point = func(name string) error {
			if name == point {
				os.Exit(79)
			}
			return nil
		}
		_, _ = prepareIn(context.Background(), area, fixtureID, o)
		t.Fatal("child missed interruption boundary")
	}
	for _, point := range []string{"before_format:audit", "before_manifest_publish", "after_manifest_publish"} {
		t.Run(point, func(t *testing.T) {
			area, path, o := fixture(t)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestStorageVolumeProcessInterruption$")
			command.Env = append(os.Environ(), "ANDEIVA_STORAGE_VOLUME_CHILD="+point, "ANDEIVA_STORAGE_VOLUME_FIXTURE="+path)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 79 {
				t.Fatalf("child did not exit at boundary: %v %s", err, output)
			}
			snapshot, err := inspectIn(context.Background(), area, fixtureID, o)
			if point == "after_manifest_publish" {
				if err != nil || snapshot.State != "inactive_preparation" {
					t.Fatal("completed images not readable", err)
				}
			} else if err == nil {
				t.Fatal("partial images selected")
			}
			if _, err = prepareIn(context.Background(), area, fixtureID, o); !errors.Is(err, ErrExists) {
				t.Fatal("restart reused partial files", err)
			}
		})
	}
}

func TestBaseEntriesRefuseForeignNamesAndMultiplePreparations(t *testing.T) {
	for _, names := range [][]string{nil, {"preparation.lock"}, {"preparation.lock", "volumes-" + fixtureID}} {
		if !validBaseEntries(names) {
			t.Fatal("valid base shape refused")
		}
	}
	for _, names := range [][]string{{"foreign"}, {"volumes-" + fixtureID}, {"preparation.lock", "../escape"}, {"preparation.lock", "volumes-" + fixtureID, "volumes-" + strings.Repeat("a", 32)}} {
		if validBaseEntries(names) {
			t.Fatal("foreign or ambiguous base accepted")
		}
	}
}

func TestTrustedSystemInputsAreAnExactAllowlist(t *testing.T) {
	for _, name := range []string{"", "relative", "/etc/passwd", "/usr/lib/../lib/os-release", "/dev/sda"} {
		if _, err := trustedOpen(name); !errors.Is(err, ErrUnsafe) {
			t.Fatal("unreviewed system file opened", err)
		}
	}
}
