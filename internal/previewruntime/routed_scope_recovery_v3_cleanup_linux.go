//go:build linux

package previewruntime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type scopeRecoveryCleanupV3 struct {
	area        *os.Root
	children    [3]*os.Root // netns, ipc, api
	directories [4]os.FileInfo
	metadata    os.FileInfo
	sockets     map[string]os.FileInfo
	record      RoutedScopeRecoveryRecordV3
}

func scopeCleanupDirectoryV3(area *os.Root, uid, gid uint32, mode os.FileMode) (os.FileInfo, error) {
	file, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Gid != gid || info.Mode() != os.ModeDir|mode || !fenceNoACLV3(file, true) {
		return nil, ErrIdentity
	}
	return info, nil
}
func scopeCleanupEntriesV3(area *os.Root, max int) ([]os.DirEntry, error) {
	if area == nil || max < 0 || max > 4 {
		return nil, ErrIdentity
	}
	file, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(max + 1)
	if err != nil && err != io.EOF || len(entries) > max {
		return nil, ErrIdentity
	}
	return entries, nil
}
func scopeCleanupSocketV3(area *os.Root, name string, ids Identities) (os.FileInfo, error) {
	if name != "routed.sock" && name != "compat.sock" {
		return nil, ErrIdentity
	}
	info, err := area.Lstat(name)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != os.ModeSocket|0660 || st.Uid != ids.HelperUID || st.Gid != ids.IPCGID || st.Nlink != 1 {
		return nil, ErrIdentity
	}
	directory, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// No socket open/connect. The descriptor-anchored no-follow xattr query checks
	// the filesystem node; identities are checked again before any unlink.
	_, err = unix.Lgetxattr(fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), name), "system.posix_acl_access", nil)
	if !errors.Is(err, unix.ENODATA) {
		return nil, ErrIdentity
	}
	after, err := area.Lstat(name)
	if err != nil || !os.SameFile(info, after) {
		return nil, ErrIdentity
	}
	return info, nil
}
func (c *scopeRecoveryCleanupV3) checkMetadata() error {
	file, err := c.area.OpenFile("runtime.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != 0644 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || !fenceNoACLV3(file, false) || (c.metadata != nil && !os.SameFile(c.metadata, info)) {
		return ErrIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 || retirementDigestV3(raw) != c.record.MetadataSHA256 {
		return ErrIdentity
	}
	current, err := c.area.Lstat("runtime.json")
	if err != nil || !os.SameFile(current, info) {
		return ErrIdentity
	}
	c.metadata = info
	return nil
}
func prepareScopeRecoveryCleanupV3(area *os.Root, record RoutedScopeRecoveryRecordV3) (out *scopeRecoveryCleanupV3, result error) {
	if area == nil || !record.valid() || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	c := &scopeRecoveryCleanupV3{area: area, record: record, sockets: map[string]os.FileInfo{}}
	defer func() {
		if result != nil {
			_ = c.Close()
		}
	}()
	var err error
	c.directories[0], err = scopeCleanupDirectoryV3(area, 0, 0, 0755)
	if err != nil {
		return nil, err
	}
	entries, err := scopeCleanupEntriesV3(area, 4)
	if err != nil || len(entries) != 4 {
		return nil, ErrIdentity
	}
	allowed := map[string]bool{"runtime.json": true, "netns": true, "ipc": true, "api": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrIdentity
		}
	}
	if err = c.checkMetadata(); err != nil {
		return nil, err
	}
	for i, item := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
	}{{"netns", 0, 0, 0700}, {"ipc", record.Identities.HelperUID, record.Identities.IPCGID, 0750}, {"api", record.Identities.APIUID, record.Identities.APIGID, 0700}} {
		c.children[i], err = area.OpenRoot(item.name)
		if err != nil {
			return nil, err
		}
		c.directories[i+1], err = scopeCleanupDirectoryV3(c.children[i], item.uid, item.gid, item.mode)
		if err != nil {
			return nil, err
		}
		named, err := area.Lstat(item.name)
		if err != nil || !os.SameFile(named, c.directories[i+1]) {
			return nil, ErrIdentity
		}
	}
	st := c.directories[1].Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != record.Directory.Device || st.Ino != record.Directory.Inode {
		return nil, ErrIdentity
	}
	entries, err = scopeCleanupEntriesV3(c.children[0], 1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "gateway" {
		return nil, ErrIdentity
	}
	entries, err = scopeCleanupEntriesV3(c.children[2], 0)
	if err != nil || len(entries) != 0 {
		return nil, ErrIdentity
	}
	entries, err = scopeCleanupEntriesV3(c.children[1], 2)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		info, err := scopeCleanupSocketV3(c.children[1], entry.Name(), record.Identities)
		if err != nil {
			return nil, err
		}
		c.sockets[entry.Name()] = info
	}
	return c, nil
}

// Remove only typed, pre-observed stale nodes. Root uses its existing CAP_CHOWN
// on the exact IPC directory after drainage; no DAC_OVERRIDE or recursive delete.
func (c *scopeRecoveryCleanupV3) removeChildren() error {
	if c == nil || c.checkMetadata() != nil {
		return ErrIdentity
	}
	parent, err := scopeCleanupDirectoryV3(c.area, 0, 0, 0755)
	if err != nil || !os.SameFile(parent, c.directories[0]) {
		return ErrIdentity
	}
	for i, item := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
	}{{"netns", 0, 0, 0700}, {"ipc", c.record.Identities.HelperUID, c.record.Identities.IPCGID, 0750}, {"api", c.record.Identities.APIUID, c.record.Identities.APIGID, 0700}} {
		current, err := c.area.Lstat(item.name)
		if err != nil || !os.SameFile(current, c.directories[i+1]) {
			return ErrIdentity
		}
		checked, err := scopeCleanupDirectoryV3(c.children[i], item.uid, item.gid, item.mode)
		if err != nil || !os.SameFile(checked, current) {
			return ErrIdentity
		}
	}
	entries, err := scopeCleanupEntriesV3(c.children[0], 0)
	if err != nil || len(entries) != 0 {
		return ErrIdentity
	}
	entries, err = scopeCleanupEntriesV3(c.children[2], 0)
	if err != nil || len(entries) != 0 {
		return ErrIdentity
	}
	entries, err = scopeCleanupEntriesV3(c.children[1], 2)
	if err != nil || len(entries) != len(c.sockets) {
		return ErrIdentity
	}
	for _, entry := range entries {
		expected, exists := c.sockets[entry.Name()]
		if !exists {
			return ErrIdentity
		}
		info, err := scopeCleanupSocketV3(c.children[1], entry.Name(), c.record.Identities)
		if err != nil || !os.SameFile(info, expected) {
			return ErrIdentity
		}
	}
	ipc, err := c.children[1].Open(".")
	if err != nil {
		return err
	}
	defer ipc.Close()
	info, err := ipc.Stat()
	if err != nil || !os.SameFile(info, c.directories[2]) || !fenceNoACLV3(ipc, true) {
		return ErrIdentity
	}
	if len(c.sockets) > 0 {
		if err = ipc.Chown(0, 0); err != nil {
			return err
		}
		info, err = scopeCleanupDirectoryV3(c.children[1], 0, 0, 0750)
		if err != nil || !os.SameFile(info, c.directories[2]) {
			return ErrIdentity
		}
		for _, name := range []string{"routed.sock", "compat.sock"} {
			expected, exists := c.sockets[name]
			if !exists {
				continue
			}
			actual, err := scopeCleanupSocketV3(c.children[1], name, c.record.Identities)
			if err != nil || !os.SameFile(actual, expected) {
				return ErrIdentity
			}
			if err = c.children[1].Remove(name); err != nil {
				return err
			}
		}
		if err = ipc.Sync(); err != nil {
			return err
		}
	}
	for i, name := range []string{"netns", "ipc", "api"} {
		current, err := c.area.Lstat(name)
		if err != nil || !os.SameFile(current, c.directories[i+1]) {
			return ErrIdentity
		}
		if err = c.area.Remove(name); err != nil {
			return err
		}
	}
	return nil
}
func (c *scopeRecoveryCleanupV3) removeMetadata() error {
	if c == nil || c.checkMetadata() != nil {
		return ErrIdentity
	}
	entries, err := scopeCleanupEntriesV3(c.area, 1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "runtime.json" {
		return ErrIdentity
	}
	if err = c.area.Remove("runtime.json"); err != nil {
		return err
	}
	directory, err := c.area.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err = directory.ReadDir(1)
	if err != nil && err != io.EOF || len(entries) != 0 {
		return ErrIdentity
	}
	return directory.Sync()
}
func (c *scopeRecoveryCleanupV3) Close() error {
	if c == nil {
		return nil
	}
	var result error
	for i, child := range c.children {
		if child != nil {
			result = errors.Join(result, child.Close())
			c.children[i] = nil
		}
	}
	return result
}
