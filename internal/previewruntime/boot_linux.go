//go:build linux

package previewruntime

import (
	"os"
	"path/filepath"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

type bootMarker struct {
	Version int    `json:"version"`
	BootID  string `json:"boot_id"`
}

// recoverBoot publishes the marker only after durable engine recovery and its
// helper readback barrier have completed. A missing marker always selects Startup.
func recoverBoot(path, boot string, uid, gid uint32, recover func(bool) error) error {
	if !bootPattern.MatchString(boot) || ownedDirectory(path, uid, gid, 0700) != nil {
		return ErrStorage
	}
	markerPath := filepath.Join(path, "boot.json")
	changed := true
	if _, e := os.Lstat(markerPath); e == nil {
		b, e := readOwned(markerPath, uid, gid, 0600, 4096)
		var old bootMarker
		if e != nil || firewallipc.Decode(b, &old) != nil || old.Version != 1 || !bootPattern.MatchString(old.BootID) {
			return ErrStorage
		}
		changed = old.BootID != boot
	} else if !os.IsNotExist(e) {
		return ErrStorage
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return ErrStorage
	}
	defer root.Close()
	// A previous interrupted publication is safe to replace only when it is an
	// owned, valid marker. Unknown files are preserved and require operator action.
	if _, e = root.Lstat("boot.next"); e == nil {
		b, e := readOwned(filepath.Join(path, "boot.next"), uid, gid, 0600, 4096)
		var old bootMarker
		if e != nil || firewallipc.Decode(b, &old) != nil || old.Version != 1 || !bootPattern.MatchString(old.BootID) {
			return ErrStorage
		}
		if root.Remove("boot.next") != nil {
			return ErrStorage
		}
	} else if !os.IsNotExist(e) {
		return ErrStorage
	}
	if e := recover(changed); e != nil {
		return e
	}
	if !changed {
		return nil
	}
	if writeNew(root, "boot.next", marshal(bootMarker{Version: 1, BootID: boot}), 0600, uid, gid) != nil {
		return ErrStorage
	}
	if root.Rename("boot.next", "boot.json") != nil {
		return ErrStorage
	}
	return syncDirectory(path)
}
