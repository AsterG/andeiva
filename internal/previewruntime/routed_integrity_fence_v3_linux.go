//go:build linux

package previewruntime

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const routedIntegrityFenceNameV3 = "integrity-fence"
const routedIntegrityFenceSizeV3 = 4096
const routedIntegrityFenceHeaderV3 = "ANDEIVA-INTEGRITY-FENCE-V3\n"
const routedIntegrityFenceStateV3 = len(routedIntegrityFenceHeaderV3)

var errRoutedIntegrityFenceV3 = errors.New("ANDEIVA_INTEGRITY_FENCED")

// This is a one-way private latch, not configuration or proof of readiness.
// area is borrowed; the directory/file descriptors below are owned by the latch.
type routedIntegrityFenceV3 struct {
	mu                 sync.Mutex
	area               *os.Root
	directory, file    *os.File
	rootInfo, fileInfo os.FileInfo
	uid, gid           uint32
	blocked, closed    bool
	writeAt            func([]byte, int64) (int, error)
	syncFile           func() error
}

func fenceNoACLV3(file *os.File, directory bool) bool {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		if _, err := unix.Fgetxattr(int(file.Fd()), name, nil); !errors.Is(err, unix.ENODATA) {
			return false
		}
	}
	return true
}
func fenceOwnerV3(info os.FileInfo, uid, gid uint32) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return s, ok && s.Uid == uid && s.Gid == gid
}
func fenceDirectoryV3(area *os.Root, uid, gid uint32) (*os.File, os.FileInfo, error) {
	if area == nil || uid == 0 || gid == 0 || int64(os.Geteuid()) != int64(uid) || int64(os.Getegid()) != int64(gid) {
		return nil, nil, errRoutedIntegrityFenceV3
	}
	directory, err := area.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errRoutedIntegrityFenceV3
	}
	info, err := directory.Stat()
	_, owned := fenceOwnerV3(info, uid, gid)
	if err != nil || !owned || info.Mode() != os.ModeDir|0700 || !fenceNoACLV3(directory, true) {
		_ = directory.Close()
		return nil, nil, errRoutedIntegrityFenceV3
	}
	return directory, info, nil
}
func fenceFileProfileV3(file *os.File, info, root os.FileInfo, uid, gid uint32) bool {
	if file == nil || root == nil {
		return false
	}
	s, owned := fenceOwnerV3(info, uid, gid)
	r, rok := root.Sys().(*syscall.Stat_t)
	if !owned || !rok || info.Mode() != 0600 || info.Size() != routedIntegrityFenceSizeV3 || s.Nlink != 1 || s.Dev != r.Dev || s.Blocks < routedIntegrityFenceSizeV3/512 {
		return false
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	return err == nil && flags&unix.O_ACCMODE == unix.O_RDWR && flags&(unix.O_APPEND|unix.O_TRUNC) == 0 && fenceNoACLV3(file, false)
}

// prepare is an explicit installer/test operation on an already-owned empty
// root. Failure leaves evidence in place; it never repairs or removes a file.
func prepareRoutedIntegrityFenceV3(area *os.Root, uid, gid uint32) (result error) {
	directory, root, err := fenceDirectoryV3(area, uid, gid)
	if err != nil {
		return err
	}
	defer func() {
		if directory.Close() != nil {
			result = errRoutedIntegrityFenceV3
		}
	}()
	if unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errRoutedIntegrityFenceV3
	}
	entries, err := directory.ReadDir(1)
	if err != io.EOF || len(entries) != 0 {
		return errRoutedIntegrityFenceV3
	}
	file, err := area.OpenFile(routedIntegrityFenceNameV3, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return errRoutedIntegrityFenceV3
	}
	defer func() {
		if file.Close() != nil {
			result = errRoutedIntegrityFenceV3
		}
	}()
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Fallocate(int(file.Fd()), 0, 0, routedIntegrityFenceSizeV3) != nil {
		return errRoutedIntegrityFenceV3
	}
	payload := make([]byte, routedIntegrityFenceSizeV3)
	copy(payload, routedIntegrityFenceHeaderV3)
	if n, err := file.WriteAt(payload, 0); err != nil || n != len(payload) {
		return errRoutedIntegrityFenceV3
	}
	info, err := file.Stat()
	if err != nil || !fenceFileProfileV3(file, info, root, uid, gid) {
		return errRoutedIntegrityFenceV3
	}
	named, err := area.Lstat(routedIntegrityFenceNameV3)
	if err != nil || !os.SameFile(info, named) || named.Mode() != info.Mode() {
		return errRoutedIntegrityFenceV3
	}
	if file.Sync() != nil || directory.Sync() != nil {
		return errRoutedIntegrityFenceV3
	}
	return nil
}

func openRoutedIntegrityFenceV3(area *os.Root, uid, gid uint32) (*routedIntegrityFenceV3, error) {
	directory, root, err := fenceDirectoryV3(area, uid, gid)
	if err != nil {
		return nil, err
	}
	file, err := area.OpenFile(routedIntegrityFenceNameV3, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = directory.Close()
		return nil, errRoutedIntegrityFenceV3
	}
	g := &routedIntegrityFenceV3{area: area, directory: directory, file: file, rootInfo: root, uid: uid, gid: gid, writeAt: file.WriteAt, syncFile: file.Sync}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = g.Close()
		return nil, errRoutedIntegrityFenceV3
	}
	g.fileInfo, err = file.Stat()
	if err != nil {
		_ = g.Close()
		return nil, errRoutedIntegrityFenceV3
	}
	// A valid blocked marker must remain open/locked so its owner can retain the
	// one-way fence across reconnects. Malformed profiles never become handles.
	state, err := g.readLocked()
	if err != nil {
		_ = g.Close()
		return nil, errRoutedIntegrityFenceV3
	}
	g.blocked = state == 1
	return g, nil
}
func (g *routedIntegrityFenceV3) readLocked() (byte, error) {
	if g.closed || g.file == nil || g.directory == nil {
		return 0, errRoutedIntegrityFenceV3
	}
	root, err := g.directory.Stat()
	namedRoot, e := g.area.Stat(".")
	_, owner := fenceOwnerV3(root, g.uid, g.gid)
	if err != nil || e != nil || !owner || root.Mode() != os.ModeDir|0700 || !os.SameFile(root, g.rootInfo) || !os.SameFile(root, namedRoot) || !fenceNoACLV3(g.directory, true) {
		return 0, errRoutedIntegrityFenceV3
	}
	info, err := g.file.Stat()
	named, e := g.area.Lstat(routedIntegrityFenceNameV3)
	if err != nil || e != nil || !fenceFileProfileV3(g.file, info, root, g.uid, g.gid) || !os.SameFile(info, g.fileInfo) || !os.SameFile(info, named) || named.Mode() != info.Mode() {
		return 0, errRoutedIntegrityFenceV3
	}
	var data [routedIntegrityFenceSizeV3]byte
	if n, err := g.file.ReadAt(data[:], 0); err != nil || n != len(data) {
		return 0, errRoutedIntegrityFenceV3
	}
	if !bytes.Equal(data[:routedIntegrityFenceStateV3], []byte(routedIntegrityFenceHeaderV3)) || data[routedIntegrityFenceStateV3] > 1 {
		return 0, errRoutedIntegrityFenceV3
	}
	for _, value := range data[routedIntegrityFenceStateV3+1:] {
		if value != 0 {
			return 0, errRoutedIntegrityFenceV3
		}
	}
	after, err := g.file.Stat()
	afterNamed, e := g.area.Lstat(routedIntegrityFenceNameV3)
	if err != nil || e != nil || !fenceSameStatV3(info, after) || !fenceSameStatV3(after, afterNamed) {
		return 0, errRoutedIntegrityFenceV3
	}
	afterRoot, rootErr := g.directory.Stat()
	namedAfterRoot, nameErr := g.area.Stat(".")
	if rootErr != nil || nameErr != nil || !fenceSameStatV3(root, afterRoot) || !fenceSameStatV3(afterRoot, namedAfterRoot) {
		return 0, errRoutedIntegrityFenceV3
	}
	return data[routedIntegrityFenceStateV3], nil
}
func fenceSameStatV3(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}
func (g *routedIntegrityFenceV3) Check() error {
	if g == nil {
		return errRoutedIntegrityFenceV3
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.readLocked()
	if err != nil || state == 1 {
		g.blocked = true
	}
	if g.blocked || g.closed {
		return errRoutedIntegrityFenceV3
	}
	return nil
}
func (g *routedIntegrityFenceV3) MarkBlocked() error {
	if g == nil {
		return errRoutedIntegrityFenceV3
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = true
	if _, err := g.readLocked(); err != nil {
		return err
	}
	if n, err := g.writeAt([]byte{1}, int64(routedIntegrityFenceStateV3)); err != nil || n != 1 {
		return errRoutedIntegrityFenceV3
	}
	if g.syncFile() != nil {
		return errRoutedIntegrityFenceV3
	}
	state, err := g.readLocked()
	if err != nil || state != 1 {
		return errRoutedIntegrityFenceV3
	}
	return nil
}
func (g *routedIntegrityFenceV3) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = true
	if g.closed {
		return nil
	}
	g.closed = true
	var err error
	if g.file != nil {
		err = errors.Join(err, g.file.Close())
	}
	if g.directory != nil {
		err = errors.Join(err, g.directory.Close())
	}
	if err != nil {
		return errRoutedIntegrityFenceV3
	}
	return nil
}
