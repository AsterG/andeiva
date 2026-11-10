//go:build linux

package previewruntime

import (
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

func safeParents(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrStorage
		}
		if st.Mode().Perm()&0022 != 0 && !(st.Mode()&os.ModeSticky != 0 && st.Sys().(*syscall.Stat_t).Uid == 0) {
			return ErrStorage
		}
		if p == "/" {
			return nil
		}
	}
}
func readOwned(path string, uid, gid uint32, mode os.FileMode, limit int64) ([]byte, error) {
	if safeParents(path) != nil {
		return nil, ErrStorage
	}
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, ErrStorage
	}
	defer root.Close()
	f, e := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrStorage
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != mode || st.Size() > limit {
		return nil, ErrStorage
	}
	owner := st.Sys().(*syscall.Stat_t)
	if owner.Uid != uid || owner.Gid != gid || owner.Nlink != 1 {
		return nil, ErrStorage
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrStorage
	}
	return b, nil
}
func LoadConfig(path string) (Config, error) {
	var c Config
	if path != ConfigPath {
		return c, ErrConfiguration
	}
	b, e := readOwned(path, 0, 0, 0644, 8192)
	if e != nil {
		return c, e
	}
	if firewallipc.Decode(b, &c) != nil {
		return c, ErrConfiguration
	}
	return c, c.Validate()
}
func resolve(c Config) (Identities, error) {
	var ids Identities
	a, e := user.Lookup(c.APIUser)
	if e != nil {
		return ids, ErrIdentity
	}
	h, e := user.Lookup(c.HelperUser)
	if e != nil {
		return ids, ErrIdentity
	}
	au, e := strconv.ParseUint(a.Uid, 10, 32)
	if e != nil {
		return ids, ErrIdentity
	}
	ag, e := strconv.ParseUint(a.Gid, 10, 32)
	if e != nil {
		return ids, ErrIdentity
	}
	hu, e := strconv.ParseUint(h.Uid, 10, 32)
	if e != nil {
		return ids, ErrIdentity
	}
	group, e := user.LookupGroup(c.IPCGroup)
	if e != nil {
		return ids, ErrIdentity
	}
	ig, e := strconv.ParseUint(group.Gid, 10, 32)
	if e != nil {
		return ids, ErrIdentity
	}
	ids = Identities{SchemaVersion: 1, APIUID: uint32(au), APIGID: uint32(ag), HelperUID: uint32(hu), IPCGID: uint32(ig)}
	return ids, ids.Validate()
}
func LoadIdentities(c Config) (Identities, error) {
	var ids Identities
	b, e := readOwned(DataDir+"/identities.json", 0, 0, 0644, 4096)
	if e != nil {
		return ids, e
	}
	if firewallipc.Decode(b, &ids) != nil || ids.Validate() != nil {
		return ids, ErrIdentity
	}
	actual, e := resolve(c)
	if e != nil || actual != ids {
		return ids, ErrIdentity
	}
	return ids, nil
}
func ReadMetadata() (Metadata, error) {
	var m Metadata
	b, e := readOwned(RuntimeDir+"/runtime.json", 0, 0, 0644, 8192)
	if e != nil {
		return m, e
	}
	if firewallipc.Decode(b, &m) != nil || m.Validate() != nil {
		return m, ErrConfiguration
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return m, ErrConfiguration
	}
	id, e := canonicalBoot(boot)
	if e != nil || id != m.BootID {
		return m, ErrConfiguration
	}
	ns, e := namespaceID(RuntimeDir + "/netns/gateway")
	if e != nil || ns != m.GatewayNamespace {
		return m, ErrIdentity
	}
	return m, nil
}
func namespaceID(path string) (uint64, error) {
	s, e := os.Stat(path)
	if e != nil {
		return 0, ErrIdentity
	}
	n := s.Sys().(*syscall.Stat_t).Ino
	if n == 0 {
		return 0, ErrIdentity
	}
	return n, nil
}
func writeNew(root *os.Root, name string, data []byte, mode os.FileMode, uid, gid uint32) error {
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if e != nil {
		return ErrStorage
	}
	e = f.Chown(int(uid), int(gid))
	if e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrStorage
	}
	return nil
}
func marshal(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		return nil
	}
	return append(b, '\n')
}
func syncDirectory(path string) error {
	if safeParents(filepath.Join(path, ".sync")) != nil {
		return ErrStorage
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return ErrStorage
	}
	defer root.Close()
	r, e := root.Open(".")
	if e != nil {
		return ErrStorage
	}
	syncErr := r.Sync()
	closeErr := r.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStorage
	}
	return nil
}

func ownedDirectory(path string, uid, gid uint32, mode os.FileMode) error {
	if safeParents(path) != nil {
		return ErrStorage
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() || st.Mode().Perm() != mode {
		return ErrStorage
	}
	s := st.Sys().(*syscall.Stat_t)
	if s.Uid != uid || s.Gid != gid {
		return ErrStorage
	}
	return nil
}
