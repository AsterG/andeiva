//go:build linux

package storagevol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type preparationOptions struct {
	uid, gid uint32
	plans    []VolumePlan
	allocate func(*os.File, uint64) error
	format   func(context.Context, *os.File, VolumePlan) error
	space    func(*os.Root, uint64) error
	point    func(string) error
}

func defaults() preparationOptions {
	return preparationOptions{uid: 0, gid: 0, plans: LabPlan().Volumes, allocate: allocateImage, format: formatImage, space: checkSpace}
}

// Prepare allocates and formats a single inactive test set at the fixed root-only
// base. It never mounts, activates, removes, or migrates appliance data.
func Prepare(parent context.Context) (Manifest, error) {
	if parent == nil {
		return Manifest{}, ErrInvalid
	}
	if parent.Err() != nil {
		return Manifest{}, ErrStorage
	}
	if err := qualifiedPlatform(); err != nil {
		return Manifest{}, err
	}
	if err := checkFormatter(); err != nil {
		return Manifest{}, err
	}
	base, lock, err := openBase(true)
	if err != nil {
		return Manifest{}, err
	}
	defer base.Close()
	defer lock.Close()
	names, err := directoryNames(base, 3)
	if err != nil {
		return Manifest{}, err
	}
	if len(names) != 1 || names[0] != "preparation.lock" {
		return Manifest{}, ErrExists
	}
	options := defaults()
	if err = options.space(base, LabPlan().TotalBytes); err != nil {
		return Manifest{}, err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Manifest{}, ErrStorage
	}
	id := hex.EncodeToString(random[:])
	name := "volumes-" + id
	if err = base.Mkdir(name, 0700); err != nil {
		return Manifest{}, ErrStorage
	}
	if err = syncRoot(base); err != nil {
		return Manifest{ID: id}, ErrStorage
	}
	area, err := openArea(base, name, 0, 0)
	if err != nil {
		return Manifest{ID: id}, ErrStorage
	}
	defer area.Close()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	return prepareIn(ctx, area, id, options)
}

// Inspect validates the original, still-unmodified prepared images. It does not
// attest attachment state, filesystem health, or active appliance configuration.
func Inspect(ctx context.Context, id string) (Manifest, error) {
	if ctx == nil || !validID(id) {
		return Manifest{}, ErrInvalid
	}
	if err := qualifiedPlatform(); err != nil {
		return Manifest{}, err
	}
	base, lock, err := openBase(false)
	if err != nil {
		return Manifest{}, err
	}
	defer base.Close()
	defer lock.Close()
	area, err := openArea(base, "volumes-"+id, 0, 0)
	if err != nil {
		return Manifest{ID: id}, ErrIncomplete
	}
	defer area.Close()
	return inspectIn(ctx, area, id, defaults())
}

func prepareIn(ctx context.Context, area *os.Root, id string, o preparationOptions) (value Manifest, result error) {
	value = Manifest{Format: Format, State: "inactive_preparation", ID: id, Volumes: []Volume{}}
	if ctx == nil || area == nil || !validID(id) || !validPlans(o.plans) || o.allocate == nil || o.format == nil || o.space == nil {
		return value, ErrInvalid
	}
	if err := checkRoot(area, o.uid, o.gid); err != nil {
		return value, err
	}
	names, err := directoryNames(area, 1)
	if err != nil {
		if err == ErrUnsafe {
			return value, ErrExists
		}
		return value, err
	}
	if len(names) != 0 {
		return value, ErrExists
	}
	for _, p := range o.plans {
		value.TotalBytes += p.Bytes
	}
	if err = o.space(area, value.TotalBytes); err != nil {
		return value, err
	}
	for _, p := range o.plans {
		if ctx.Err() != nil {
			return value, ErrStorage
		}
		file, e := area.OpenFile(p.File, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
		if e != nil {
			return value, ErrStorage
		}
		volume, e := prepareImage(ctx, area, file, p, o)
		closeErr := file.Close()
		if e != nil {
			return value, e
		}
		if closeErr != nil {
			return value, ErrStorage
		}
		for _, previous := range value.Volumes {
			if previous.UUID == volume.UUID {
				return value, ErrUnsafe
			}
		}
		value.Volumes = append(value.Volumes, volume)
	}
	if err = syncRoot(area); err != nil {
		return value, ErrStorage
	}
	value.Hash = hashManifest(value)
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxManifestBytes {
		return value, ErrStorage
	}
	file, err := area.OpenFile(pendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return value, ErrStorage
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return value, ErrStorage
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return value, ErrStorage
	}
	pinned, err := file.Stat()
	closeErr := file.Close()
	if err != nil || closeErr != nil || !regular(pinned, o.uid, o.gid) {
		return value, ErrStorage
	}
	if err = point(o, "before_manifest_publish"); err != nil {
		return value, err
	}
	current, err := readPinned(area, pendingName, pinned, o)
	if err != nil || !bytes.Equal(current, data) {
		return value, ErrStorage
	}
	if err = publishManifest(area, o); err != nil {
		return value, err
	}
	if err = point(o, "after_manifest_publish"); err != nil {
		return value, ErrUncertain
	}
	if err = syncRoot(area); err != nil {
		return value, ErrUncertain
	}
	verified, err := inspectIn(ctx, area, id, o)
	if err != nil {
		return value, ErrUncertain
	}
	return verified, nil
}

func prepareImage(ctx context.Context, area *os.Root, file *os.File, p VolumePlan, o preparationOptions) (Volume, error) {
	created, err := file.Stat()
	if err != nil || !regular(created, o.uid, o.gid) || created.Size() != 0 {
		return Volume{}, ErrUnsafe
	}
	if err = point(o, "before_allocate:"+p.Domain); err != nil {
		return Volume{}, err
	}
	if err = o.allocate(file, p.Bytes); err != nil {
		return Volume{}, ErrCapacity
	}
	if err = file.Sync(); err != nil {
		return Volume{}, ErrStorage
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(created, info) || !allocated(info, p, o) {
		return Volume{}, ErrUnsafe
	}
	if err = point(o, "before_format:"+p.Domain); err != nil {
		return Volume{}, err
	}
	if err = o.format(ctx, file, p); err != nil {
		return Volume{}, ErrFormatter
	}
	if err = materializeImage(ctx, file, p.Bytes); err != nil {
		return Volume{}, ErrStorage
	}
	if err = file.Sync(); err != nil {
		return Volume{}, ErrStorage
	}
	if err = point(o, "after_format:"+p.Domain); err != nil {
		return Volume{}, err
	}
	value, info, err := readVolume(ctx, file, p, o)
	if err != nil {
		return Volume{}, err
	}
	pathInfo, err := area.Lstat(p.File)
	if err != nil || !sameFile(info, pathInfo) || !os.SameFile(created, pathInfo) {
		return Volume{}, ErrUnsafe
	}
	return value, nil
}

func inspectIn(ctx context.Context, area *os.Root, id string, o preparationOptions) (Manifest, error) {
	if err := checkRoot(area, o.uid, o.gid); err != nil {
		return Manifest{}, err
	}
	names, err := directoryNames(area, 7)
	if err != nil {
		return Manifest{}, err
	}
	if len(names) != len(o.plans)+1 {
		return Manifest{ID: id}, ErrIncomplete
	}
	expected := map[string]bool{manifestName: true}
	for _, p := range o.plans {
		expected[p.File] = true
	}
	for _, name := range names {
		if !expected[name] {
			return Manifest{}, ErrUnsafe
		}
	}
	info, err := area.Lstat(manifestName)
	if err != nil {
		return Manifest{ID: id}, ErrIncomplete
	}
	data, err := readPinned(area, manifestName, info, o)
	if err != nil {
		return Manifest{}, err
	}
	var value Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return Manifest{}, ErrUnsafe
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) || value.Format != Format || value.State != "inactive_preparation" || value.ID != id || value.Hash != hashManifest(value) || len(value.Volumes) != len(o.plans) {
		return Manifest{}, ErrUnsafe
	}
	var total uint64
	seenUUID := map[string]bool{}
	for i, p := range o.plans {
		expectedVolume := value.Volumes[i]
		if expectedVolume.VolumePlan != p {
			return Manifest{}, ErrUnsafe
		}
		total += p.Bytes
		file, e := area.OpenFile(p.File, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return Manifest{}, ErrUnsafe
		}
		actual, pinned, e := readVolume(ctx, file, p, o)
		closeErr := file.Close()
		if e != nil {
			return Manifest{}, e
		}
		if closeErr != nil {
			return Manifest{}, ErrStorage
		}
		pathInfo, e := area.Lstat(p.File)
		if e != nil || !sameFile(pinned, pathInfo) || actual != expectedVolume || seenUUID[actual.UUID] {
			return Manifest{}, ErrUnsafe
		}
		seenUUID[actual.UUID] = true
	}
	if value.TotalBytes != total {
		return Manifest{}, ErrUnsafe
	}
	return value, nil
}

func readVolume(ctx context.Context, file *os.File, p VolumePlan, o preparationOptions) (Volume, os.FileInfo, error) {
	if p.Bytes < 4*mib || p.Bytes > 128*mib {
		return Volume{}, nil, ErrInvalid
	}
	info, err := file.Stat()
	if err != nil || !allocated(info, p, o) {
		return Volume{}, nil, ErrUnsafe
	}
	var super [1024]byte
	if _, err = file.ReadAt(super[:], 1024); err != nil {
		return Volume{}, nil, ErrUnsafe
	}
	// These fields verify the prepared format, not a substitute for e2fsck/mount tests.
	if binary.LittleEndian.Uint16(super[0x38:]) != 0xef53 || binary.LittleEndian.Uint32(super[0x18:]) != 2 || binary.LittleEndian.Uint32(super[0:]) != p.Inodes || uint64(binary.LittleEndian.Uint32(super[4:])) != p.Bytes/4096 || binary.LittleEndian.Uint32(super[0x5c:])&4 == 0 {
		return Volume{}, nil, ErrUnsafe
	}
	uuid := hex.EncodeToString(super[0x68:0x78])
	if uuid == strings.Repeat("0", 32) {
		return Volume{}, nil, ErrUnsafe
	}
	hash := sha256.New()
	count, err := io.CopyBuffer(hash, contextReader{ctx, io.NewSectionReader(file, 0, int64(p.Bytes))}, make([]byte, 64*1024))
	if err != nil || count != int64(p.Bytes) {
		return Volume{}, nil, ErrStorage
	}
	after, err := file.Stat()
	if err != nil || !sameFile(info, after) {
		return Volume{}, nil, ErrUnsafe
	}
	blocks := fileBlocks(after)
	return Volume{VolumePlan: p, AllocatedBytes: blocks, Filesystem: "ext4", BlockSize: 4096, UUID: uuid, SHA256: hex.EncodeToString(hash.Sum(nil))}, after, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(data)
}
func point(o preparationOptions, name string) error {
	if o.point != nil {
		return o.point(name)
	}
	return nil
}
