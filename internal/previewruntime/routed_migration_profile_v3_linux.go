//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type routedProfileFileV3 struct {
	name string
	info os.FileInfo
	hash string
}
type routedProfileAreaV3 struct {
	root            *os.Root
	directory, lock *os.File
	info            os.FileInfo
	lockInfo        os.FileInfo
	lockName        string
	files           []routedProfileFileV3
}
type routedProfileScanV3 struct {
	areas         [4]routedProfileAreaV3
	owner, gid    uint32
	bytes, inodes uint64
}

func (p *routedProfileScanV3) Close() (result error) {
	if p == nil {
		return nil
	}
	for i := len(p.areas) - 1; i >= 0; i-- {
		a := &p.areas[i]
		if a.lock != nil {
			result = errors.Join(result, a.lock.Close())
			a.lock = nil
		}
		if a.directory != nil {
			result = errors.Join(result, a.directory.Close())
			a.directory = nil
		}
	}
	return result
}
func profileStatV3(info os.FileInfo, uid, gid uint32, mode os.FileMode, device uint64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode() != mode {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && st.Gid == gid && st.Nlink == 1 && st.Dev == device && st.Size >= 0
}
func profileDirectoryV3(a *routedProfileAreaV3, uid, gid uint32, mode os.FileMode) error {
	opened, e := a.directory.Stat()
	named, ne := os.Lstat(a.root.Name())
	pinned, pe := a.root.Stat(".")
	if e != nil || ne != nil || pe != nil || opened.Mode() != os.ModeDir|mode || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, named) || !os.SameFile(opened, pinned) || !os.SameFile(opened, a.info) {
		return ErrIdentity
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Gid != gid || !fenceNoACLV3(a.directory, true) {
		return ErrIdentity
	}
	return nil
}
func profileNameV3(area int, name string) bool {
	if area == 0 {
		return name == "checkpoint.lock" || name == "selected.json" || (len(name) == 76 && strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && validHex(name[7:71], 32))
	}
	if name == "pool.json" {
		return true
	}
	for i := 0; i < 18; i++ {
		if name == fmt.Sprintf("reserve-%02d.bin", i) {
			return true
		}
	}
	return false
}
func profileReadV3(ctx context.Context, a *routedProfileAreaV3, f routedProfileFileV3, uid, gid uint32, mode os.FileMode) (hash string, result error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	file, e := a.root.OpenFile(f.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", ErrIdentity
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	info, e := file.Stat()
	named, ne := a.root.Lstat(f.name)
	dirStat := a.info.Sys().(*syscall.Stat_t)
	if e != nil || ne != nil || !profileStatV3(info, uid, gid, mode, dirStat.Dev) || !os.SameFile(info, f.info) || !os.SameFile(info, named) || info.Size() != f.info.Size() || !fenceNoACLV3(file, false) {
		return "", ErrIdentity
	}
	digest := sha256.New()
	n, e := io.Copy(digest, io.LimitReader(file, (1<<20)+1))
	if e != nil || n != info.Size() || n > 1<<20 || ctx.Err() != nil {
		return "", ErrIdentity
	}
	after, e := file.Stat()
	current, ne := a.root.Lstat(f.name)
	if e != nil || ne != nil || !os.SameFile(info, after) || !os.SameFile(info, current) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || !profileStatV3(after, uid, gid, mode, dirStat.Dev) {
		return "", ErrIdentity
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// The scan retains the actual four writer locks. It checks physical metadata
// and byte identity only; it is not a root impersonation of a helper G1 reader.
func scanRoutedProfileV3(ctx context.Context, roots [4]*os.Root, uid, gid uint32, budget routedWriteBudgetV3) (out *routedProfileScanV3, result error) {
	if ctx == nil || ctx.Err() != nil || uid == 0 || gid == 0 || budget.Bytes == 0 || budget.Inodes == 0 || budget.Inodes > 32768 || budget.Bytes > 1<<30 {
		return nil, ErrIdentity
	}
	p := &routedProfileScanV3{owner: uid, gid: gid}
	defer func() {
		if result != nil {
			result = errors.Join(result, p.Close())
			out = nil
		}
	}()
	for i, root := range roots {
		if root == nil {
			return nil, ErrIdentity
		}
		a := &p.areas[i]
		a.root = root
		var e error
		a.info, e = root.Stat(".")
		if e != nil {
			return nil, ErrIdentity
		}
		for j := 0; j < i; j++ {
			if os.SameFile(a.info, p.areas[j].info) {
				return nil, ErrIdentity
			}
		}
		a.directory, e = root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
		if e != nil {
			return nil, e
		}
		if profileDirectoryV3(a, uid, gid, 0700) != nil {
			return nil, ErrIdentity
		}
		lockName := "pool.json"
		if i == 0 {
			lockName = "checkpoint.lock"
		}
		a.lockName = lockName
		a.lock, e = root.OpenFile(lockName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return nil, ErrIdentity
		}
		lockInfo, e := a.lock.Stat()
		named, ne := root.Lstat(lockName)
		st := a.info.Sys().(*syscall.Stat_t)
		if e != nil || ne != nil || !profileStatV3(lockInfo, uid, gid, 0600, st.Dev) || !os.SameFile(lockInfo, named) || !fenceNoACLV3(a.lock, false) {
			return nil, ErrIdentity
		}
		a.lockInfo = lockInfo
		if unix.Flock(int(a.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			return nil, ErrUnavailable
		}
	}
	for i := range p.areas {
		a := &p.areas[i]
		entries, e := a.directory.ReadDir(int(budget.Inodes) + 1)
		if e != nil && e != io.EOF {
			return nil, e
		}
		if i != 0 && len(entries) != 19 {
			return nil, ErrIdentity
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		selected := false
		for _, entry := range entries {
			if !profileNameV3(i, entry.Name()) {
				return nil, ErrIdentity
			}
			if entry.Name() == "selected.json" {
				selected = true
			}
			info, e := a.root.Lstat(entry.Name())
			st := a.info.Sys().(*syscall.Stat_t)
			if e != nil || !profileStatV3(info, uid, gid, 0600, st.Dev) || info.Size() < 0 || info.Size() > 1<<20 || (i == 0 && entry.Name() == "checkpoint.lock" && info.Size() != 0) || (i == 0 && entry.Name() == "selected.json" && (info.Size() == 0 || info.Size() > 4096)) {
				return nil, ErrIdentity
			}
			size := info.Size()
			if size < 0 || size > 1<<20 {
				return nil, ErrIdentity
			}
			p.bytes += uint64(size)
			p.inodes++
			if p.bytes > budget.Bytes || p.inodes > budget.Inodes {
				return nil, ErrIdentity
			}
			if entry.Name() == a.lockName && !os.SameFile(info, a.lockInfo) {
				return nil, ErrIdentity
			}
			f := routedProfileFileV3{name: entry.Name(), info: info}
			f.hash, e = profileReadV3(ctx, a, f, uid, gid, 0600)
			if e != nil {
				return nil, e
			}
			if strings.HasPrefix(f.name, "object-") && f.hash != f.name[7:71] {
				return nil, ErrIdentity
			}
			a.files = append(a.files, f)
		}
		if i == 0 && !selected {
			return nil, ErrIdentity
		}
	}
	return p, nil
}

func (p *routedProfileScanV3) revalidate(ctx context.Context, reader uint32, shared bool) error {
	for i := range p.areas {
		a := &p.areas[i]
		gid, mode := p.gid, os.FileMode(0700)
		if shared {
			gid = reader
			mode = os.ModeSetgid | 0750
		}
		if profileDirectoryV3(a, p.owner, gid, mode) != nil {
			return ErrIdentity
		}
		lockInfo, e := a.lock.Stat()
		named, ne := a.root.Lstat(a.lockName)
		if e != nil || ne != nil || !os.SameFile(lockInfo, a.lockInfo) || !os.SameFile(lockInfo, named) {
			return ErrIdentity
		}
		directory, e := a.root.Open(".")
		if e != nil {
			return e
		}
		entries, re := directory.ReadDir(len(a.files) + 1)
		ce := directory.Close()
		if (re != nil && re != io.EOF) || ce != nil || len(entries) != len(a.files) {
			return ErrIdentity
		}
		names := map[string]bool{}
		for _, entry := range entries {
			names[entry.Name()] = true
		}
		for _, f := range a.files {
			if !names[f.name] {
				return ErrIdentity
			}
			fileMode := os.FileMode(0600)
			if shared && !(i == 0 && f.name == "checkpoint.lock") {
				fileMode = 0640
			}
			hash, e := profileReadV3(ctx, a, f, p.owner, gid, fileMode)
			if e != nil || hash != f.hash {
				return ErrIdentity
			}
		}
	}
	return nil
}
func (p *routedProfileScanV3) convert(ctx context.Context, reader uint32, hook func(string) error) (access [4]routedAccessRecordV3, result error) {
	defer func() {
		if result != nil {
			access = [4]routedAccessRecordV3{}
		}
	}()
	if p == nil || ctx == nil || os.Geteuid() != 0 || reader == 0 || reader == p.gid || reader == ^uint32(0) || p.revalidate(ctx, reader, false) != nil {
		return access, ErrIdentity
	}
	at := func(point string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if hook != nil {
			return hook(point)
		}
		return nil
	}
	for i := range p.areas {
		a := &p.areas[i]
		for _, f := range a.files {
			if e := at(fmt.Sprintf("before_file:%d:%s", i, f.name)); e != nil {
				return access, e
			}
			if profileDirectoryV3(a, p.owner, p.gid, 0700) != nil {
				return access, ErrIdentity
			}
			file, e := a.root.OpenFile(f.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if e != nil {
				return access, ErrIdentity
			}
			info, e := file.Stat()
			named, ne := a.root.Lstat(f.name)
			dir := a.info.Sys().(*syscall.Stat_t)
			if e != nil || ne != nil || !profileStatV3(info, p.owner, p.gid, 0600, dir.Dev) || !os.SameFile(info, f.info) || !os.SameFile(info, named) || !fenceNoACLV3(file, false) {
				_ = file.Close()
				return access, ErrIdentity
			}
			beforeHash, readErr := profileDescriptorHashV3(ctx, file, f.info.Size())
			if readErr != nil || beforeHash != f.hash {
				_ = file.Close()
				return access, ErrIdentity
			}
			if e = file.Chown(-1, int(reader)); e != nil {
				_ = file.Close()
				return access, e
			}
			mode := os.FileMode(0640)
			if i == 0 && f.name == "checkpoint.lock" {
				mode = 0600
			}
			if e = file.Chmod(mode); e == nil {
				e = file.Sync()
			}
			after, se := file.Stat()
			current, ne := a.root.Lstat(f.name)
			valid := e == nil && se == nil && ne == nil && profileStatV3(after, p.owner, reader, mode, dir.Dev) && os.SameFile(after, current) && os.SameFile(after, f.info) && fenceNoACLV3(file, false)
			afterHash, hashErr := profileDescriptorHashV3(ctx, file, f.info.Size())
			ce := file.Close()
			if !valid || ce != nil || hashErr != nil || afterHash != f.hash {
				return access, ErrIdentity
			}
			if e = at(fmt.Sprintf("after_file:%d:%s", i, f.name)); e != nil {
				return access, e
			}
		}
		if e := at(fmt.Sprintf("before_directory:%d", i)); e != nil {
			return access, e
		}
		if profileDirectoryV3(a, p.owner, p.gid, 0700) != nil {
			return access, ErrIdentity
		}
		if e := a.directory.Chown(-1, int(reader)); e != nil {
			return access, e
		}
		if e := a.directory.Chmod(os.ModeSetgid | 0750); e != nil {
			return access, e
		}
		if e := a.directory.Sync(); e != nil {
			return access, e
		}
		if profileDirectoryV3(a, p.owner, reader, os.ModeSetgid|0750) != nil {
			return access, ErrIdentity
		}
		st := a.info.Sys().(*syscall.Stat_t)
		access[i] = routedAccessRecordV3{Version: 1, OwnerUID: p.owner, ReaderGID: reader, Device: st.Dev, Inode: st.Ino}
		if access[i].access().CheckDirectory(a.root) != nil {
			return [4]routedAccessRecordV3{}, ErrIdentity
		}
		if e := at(fmt.Sprintf("after_directory:%d", i)); e != nil {
			return [4]routedAccessRecordV3{}, e
		}
	}
	if p.revalidate(ctx, reader, true) != nil {
		return [4]routedAccessRecordV3{}, ErrIdentity
	}
	return access, nil
}

func profileDescriptorHashV3(ctx context.Context, file *os.File, size int64) (string, error) {
	if ctx == nil || ctx.Err() != nil || file == nil || size < 0 || size > 1<<20 {
		return "", ErrIdentity
	}
	if _, e := file.Seek(0, io.SeekStart); e != nil {
		return "", e
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(file, (1<<20)+1))
	if e != nil || n != size || ctx.Err() != nil {
		return "", ErrIdentity
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
