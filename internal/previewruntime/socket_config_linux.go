//go:build linux

package previewruntime

import (
	"bytes"
	"os"
)

const socketDropinDir = "/etc/systemd/system/andeiva-preview-api.socket.d"

func socketConfiguration(c Config) []byte {
	return []byte("[Socket]\nListenStream=\nListenStream=" + c.ListenAddress + "\nBindToDevice=" + c.Interface + "\n")
}
func provisionSocket(c Config) error {
	if c.Validate() != nil || safeParents(socketDropinDir) != nil {
		return ErrConfiguration
	}
	if createSocketDirectory(socketDropinDir, 0, 0) != nil {
		return ErrStorage
	}
	expected := socketConfiguration(c)
	path := socketDropinDir + "/listen.conf"
	if _, e := os.Lstat(path); e == nil {
		b, e := readOwned(path, 0, 0, 0644, 4096)
		if e != nil || !bytes.Equal(b, expected) {
			return ErrConfiguration
		}
		return nil
	} else if !os.IsNotExist(e) {
		return ErrStorage
	}
	root, e := os.OpenRoot(socketDropinDir)
	if e != nil {
		return ErrStorage
	}
	defer root.Close()
	if writeNew(root, "listen.next", expected, 0644, 0, 0) != nil {
		return ErrStorage
	}
	if root.Rename("listen.next", "listen.conf") != nil {
		return ErrStorage
	}
	return syncDirectory(socketDropinDir)
}

func createSocketDirectory(path string, uid, gid uint32) error {
	if safeParents(path) != nil {
		return ErrStorage
	}
	if err := os.Mkdir(path, 0755); err == nil {
		// Only a directory created by this invocation may be normalized. Existing
		// directories retain strict ownership and mode validation.
		if os.Chmod(path, 0755) != nil {
			return ErrStorage
		}
	} else if !os.IsExist(err) {
		return ErrStorage
	}
	return ownedDirectory(path, uid, gid, 0755)
}
