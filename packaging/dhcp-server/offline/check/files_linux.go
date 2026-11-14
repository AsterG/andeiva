package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const stateDir = "/var/backups/andeiva-dhcp-offline"
const bundleBase = "/var/lib/andeiva-dhcp-bundles"
const unit = "kea-dhcp4-server.service"
const mask = "/etc/systemd/system/" + unit
const policy = "/usr/sbin/policy-rc.d"
const guard = "#!/bin/sh\n[ \"${1-}\" != --quiet ] || shift\ncase \"${1-}\" in kea-dhcp4-server|kea-dhcp4-server.service) exit 101;; *) exit 0;; esac\n"

func secure(path string, directory bool) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != kind || st.Mode&0022 != 0 || (!directory && st.Nlink != 1) {
		return errProfile
	}
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		n, e := unix.Lgetxattr(path, attr, nil)
		if e != unix.ENODATA && e != unix.ENOTSUP {
			if e != nil {
				return e
			}
			if n > 0 {
				return errProfile
			}
		}
	}
	if path != "/" {
		return secure(filepath.Dir(path), true)
	}
	return nil
}
func readFile(path string, limit int64) ([]byte, error) {
	if e := secure(path, false); e != nil {
		return nil, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errProfile
	}
	return b, nil
}

func fileHash(path string, limit int64) (string, int64, error) {
	if e := secure(path, false); e != nil {
		return "", 0, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", 0, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil || n > limit {
		return "", 0, errProfile
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func syncDir(path string) error {
	if e := secure(path, true); e != nil {
		return e
	}
	f, e := os.Open(path) // #nosec G703 G304 -- Internal directory paths; root ownership, ancestors and ACLs are checked above.
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func create(path string, b []byte, mode os.FileMode) error {
	if e := secure(filepath.Dir(path), true); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G703 G304 -- Internal fixed-root paths and checked parent; exclusive creation cannot replace an existing entry.
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = syncDir(filepath.Dir(path))
	}
	return e
}
func absent(path string) error {
	_, e := os.Lstat(path)
	if !os.IsNotExist(e) {
		return errProfile
	}
	return nil
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (4 << 20) - b.Len()
	if n > left {
		p = p[:left]
		b.overflow = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func run(path string, args ...string) ([]byte, error) {
	switch path {
	case "/usr/bin/dpkg", "/usr/bin/systemctl", "/usr/sbin/update-rc.d":
	default:
		return nil, errProfile
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- Exact executable allowlist above; all arguments are internal constants, never shell commands.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "SYSTEMD_OFFLINE=0"}
	cmd.WaitDelay = time.Second
	out := &boundedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	e := cmd.Run()
	if e != nil || out.overflow {
		return nil, fmt.Errorf("ANDEIVA_DHCP_OFFLINE_COMMAND: %s", filepath.Base(path))
	}
	return out.Bytes(), nil
}

type observedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Link   string `json:"link,omitempty"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Dev    uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type observation struct {
	Version int            `json:"version"`
	Files   []observedFile `json:"files"`
}

// Capture contains metadata and hashes, never account/config contents. All package
// handlers are included because installed non-closure packages can own triggers.
func capture() ([]byte, error) {
	osrelease, e := readFile("/usr/lib/os-release", 8192)
	if e != nil || !bytes.Contains(osrelease, []byte("\nID=debian\n")) || !bytes.Contains(osrelease, []byte("VERSION_ID=\"13\"")) {
		return nil, fmt.Errorf("%w: capture os-release", errProfile)
	}
	arch, e := run("/usr/bin/dpkg", "--print-architecture")
	if e != nil || string(arch) != "amd64\n" {
		return nil, fmt.Errorf("%w: capture architecture", errProfile)
	}
	foreign, e := run("/usr/bin/dpkg", "--print-foreign-architectures")
	if e != nil || len(foreign) != 0 {
		return nil, fmt.Errorf("%w: capture foreign architectures", errProfile)
	}
	status, e := readFile("/var/lib/dpkg/status", 8<<20)
	if e != nil {
		return nil, fmt.Errorf("capture status read: %w", e)
	}
	if e := baseline(status, false); e != nil {
		return nil, fmt.Errorf("capture baseline: %w", e)
	}
	audit, e := run("/usr/bin/dpkg", "--audit")
	if e != nil || len(audit) != 0 {
		return nil, fmt.Errorf("%w: capture dpkg audit", errProfile)
	}
	for _, p := range []string{policy, mask, "/etc/systemd/system/kea-dhcp4-server.service.d", "/run/systemd/system/kea-dhcp4-server.service", "/run/systemd/system/kea-dhcp4-server.service.d", "/etc/kea", "/var/lib/kea", "/var/log/kea", "/run/kea", "/run/lock/kea", "/etc/init.d/kea-dhcp4-server", "/usr/sbin/kea-dhcp4", "/usr/sbin/kea-lfc", "/etc/mysql", "/etc/alternatives/my.cnf", "/var/lib/dpkg/alternatives/my.cnf", "/etc/apparmor.d/usr.sbin.kea-dhcp4", "/etc/apparmor.d/usr.sbin.kea-lfc", "/var/lib/systemd/deb-systemd-helper-masked/kea-dhcp4-server.service", "/var/lib/systemd/deb-systemd-helper-enabled/kea-dhcp4-server.service.dsh-also"} {
		if absent(p) != nil {
			return nil, fmt.Errorf("%w: capture expected absence %s", errProfile, p)
		}
	}
	for _, p := range []string{"/etc/passwd", "/etc/group"} {
		b, e := readFile(p, 1<<20)
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "_kea:") {
				return nil, fmt.Errorf("%w: capture existing identity %s", errProfile, p)
			}
		}
	}
	nss, e := readFile("/etc/nsswitch.conf", 64<<10)
	if e != nil {
		return nil, e
	}
	seenNSS := map[string]bool{}
	for _, line := range strings.Split(string(nss), "\n") {
		line = strings.SplitN(line, "#", 2)[0]
		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 || (p[0] != "passwd" && p[0] != "group") {
			continue
		}
		if seenNSS[p[0]] {
			return nil, errProfile
		}
		seenNSS[p[0]] = true
		for _, source := range strings.Fields(p[1]) {
			if source != "files" && source != "systemd" {
				return nil, fmt.Errorf("%w: fresh local-only NSS required", errProfile)
			}
		}
	}
	if len(seenNSS) != 2 {
		return nil, errProfile
	}
	state, e := run("/usr/bin/systemctl", "show", unit, "--property=LoadState", "--property=MainPID", "--property=ActiveState")
	if e != nil || !bytes.Contains(state, []byte("LoadState=not-found\n")) || !bytes.Contains(state, []byte("MainPID=0\n")) || !bytes.Contains(state, []byte("ActiveState=inactive\n")) {
		return nil, fmt.Errorf("%w: capture unit not absent/inactive", errProfile)
	}
	helpers := map[string]string{"/usr/bin/deb-systemd-helper": "a895d5f077651960b6ca4ed9c53f8b36eae422ae170f61c972d0c6579e9f8732", "/usr/bin/deb-systemd-invoke": "92eadae89f4df4cd6088f6316f5390b685faf8d0e312a4e5af3a507caaf81bdb", "/usr/sbin/invoke-rc.d": "1d389fa6f6297e77b2ba1d2df4a6ec60f4d4d37815b727889f38ba602e713f77"}
	paths := []string{"/usr/lib/os-release", "/var/lib/dpkg/status", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/diversions", "/etc/dpkg/dpkg.cfg"}
	for p, want := range helpers {
		b, e := readFile(p, 1<<20)
		if e != nil || sha(b) != want {
			return nil, fmt.Errorf("%w: capture helper hash/profile %s", errProfile, p)
		}
		paths = append(paths, p)
	}
	for _, root := range []string{"/var/lib/dpkg/info", "/var/lib/dpkg/triggers", "/var/lib/dpkg/alternatives", "/etc/dpkg/dpkg.cfg.d", "/etc/apparmor.d", "/etc/systemd/system", "/run/systemd/system", "/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d"} {
		if e := secure(root, true); e != nil {
			return nil, fmt.Errorf("capture directory %s: %w", root, e)
		}
		e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if len(paths) > 8192 {
				return errProfile
			}
			if d.IsDir() {
				return nil
			}
			if root == "/var/lib/dpkg/triggers" && d.Name() == "Lock" {
				return nil
			}
			if root == "/var/lib/dpkg/info" {
				ext := filepath.Ext(path)
				if ext != ".preinst" && ext != ".postinst" && ext != ".prerm" && ext != ".postrm" && ext != ".triggers" && ext != ".conffiles" {
					return nil
				}
			}
			paths = append(paths, path)
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	sort.Strings(paths)
	result := observation{Version: 1}
	for _, p := range paths {
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); e != nil {
			return nil, e
		}
		item := observedFile{Path: p, Mode: st.Mode, UID: st.Uid, GID: st.Gid, Dev: st.Dev, Inode: st.Ino}
		if st.Uid != 0 || st.Mode&0022 != 0 && st.Mode&unix.S_IFMT != unix.S_IFLNK {
			return nil, fmt.Errorf("%w: capture ownership/mode %s", errProfile, p)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			v, e := os.Readlink(p)
			if e != nil {
				return nil, e
			}
			item.Link = v
		} else {
			b, e := readFile(p, 8<<20)
			if e != nil {
				return nil, fmt.Errorf("capture file %s: %w", p, e)
			}
			item.SHA256 = sha(b)
		}
		result.Files = append(result.Files, item)
	}
	return json.Marshal(result)
}
