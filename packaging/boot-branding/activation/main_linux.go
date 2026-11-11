//go:build linux

// Command activation is an explicit local operator tool, never an API helper.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	privateDir = "var/backups/andeiva-boot-branding"
	journal    = privateDir + "/journal.json"
	logoHash   = "1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81"
	dropin     = "# Owned by ANDEIVA boot branding; recovery menu remains visible.\nGRUB_DISTRIBUTOR=ANDEIVA\nGRUB_THEME=/usr/share/grub/themes/andeiva/theme.txt\nGRUB_TIMEOUT_STYLE=menu\nGRUB_TIMEOUT=5\nGRUB_DISABLE_RECOVERY=false\nGRUB_GFXMODE=auto\nGRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE_LINUX_DEFAULT} quiet splash loglevel=3 systemd.show_status=error\"\n"
	maxConfig  = 4 << 20
	maxImage   = 256 << 20
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+~-]{0,96}$`)

type record struct {
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	SHA256  string `json:"sha256"`
}

type state struct {
	Version   int               `json:"version"`
	Kernel    string            `json:"kernel"`
	Alternate string            `json:"alternate"`
	Phase     string            `json:"phase"`
	Pending   string            `json:"pending"`
	Before    map[string]record `json:"before"`
	Observed  map[string]record `json:"observed"`
	Context   map[string]record `json:"context"`
}

type machine struct {
	Kernel, Alternate string
	Free, Inodes      uint64
}

// The test seams are private and have no command-line or environment equivalent.
type system struct {
	root        *os.Root
	owner       uint32
	probe       func() (machine, error)
	run         func(string, string) error
	diagnostics func() error
}

func fail(code string) error { return errors.New(code) }

func target(id, kernel string) (string, error) {
	if !versionPattern.MatchString(kernel) {
		return "", fail("ANDEIVA_BOOT_KERNEL")
	}
	switch id {
	case "dropin":
		return "etc/default/grub.d/99-andeiva-branding.cfg", nil
	case "plymouth":
		return "etc/plymouth/plymouthd.conf", nil
	case "grub":
		return "boot/grub/grub.cfg", nil
	case "initrd":
		return "boot/initrd.img-" + kernel, nil
	case "defaults":
		return "etc/default/grub", nil
	case "alternate-image":
		return "boot/initrd.img-" + kernel, nil
	case "alternate-kernel", "current-kernel":
		return "boot/vmlinuz-" + kernel, nil
	}
	return "", fail("ANDEIVA_BOOT_IDENTIFIER")
}

func (s *system) secure(name string, optional bool) (fs.FileInfo, error) {
	parts := strings.Split(name, "/")
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		info, err := s.root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) && optional && i == len(parts)-1 {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != s.owner || info.Mode()&0o022 != 0 || info.Mode()&fs.ModeSymlink != 0 {
			return nil, fail("ANDEIVA_BOOT_UNSAFE_PATH")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fail("ANDEIVA_BOOT_UNSAFE_PATH")
		}
		if i == len(parts)-1 {
			return info, nil
		}
	}
	return nil, fail("ANDEIVA_BOOT_UNSAFE_PATH")
}

func limitFor(name string) int64 {
	if strings.Contains(name, "initrd") || strings.HasSuffix(name, "initrd.original") {
		return maxImage
	}
	if strings.Contains(name, "vmlinuz-") {
		return 64 << 20
	}
	return maxConfig
}

func (s *system) digest(name string, optional bool) (record, error) {
	info, err := s.secure(name, optional)
	if err != nil || info == nil {
		return record{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > limitFor(name) {
		return record{}, fail("ANDEIVA_BOOT_FILE_TYPE_OR_SIZE")
	}
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return record{}, err
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limitFor(name)+1))
	if err != nil || n != info.Size() {
		return record{}, fail("ANDEIVA_BOOT_FILE_CHANGED")
	}
	return record{true, n, uint32(info.Mode().Perm()), hex.EncodeToString(hash.Sum(nil))}, nil
}

func (s *system) readSmall(name string, optional bool) ([]byte, error) {
	info, err := s.secure(name, optional)
	if err != nil || info == nil {
		return nil, err
	}
	limit := int64(maxConfig)
	if name == journal {
		limit = 64 << 10
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fail("ANDEIVA_BOOT_FILE_TYPE_OR_SIZE")
	}
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fail("ANDEIVA_BOOT_FILE_SIZE")
	}
	return data, err
}

func (s *system) syncDir(name string) error {
	f, err := s.root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

func (s *system) atomic(name string, data []byte, mode fs.FileMode) error {
	if _, err := s.secure(name, true); err != nil {
		return err
	}
	f, err := s.root.OpenFile(name+".andeiva-next", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := s.root.Rename(name+".andeiva-next", name); err != nil {
		return err
	}
	return s.syncDir(path.Dir(name))
}

func (s *system) copyFile(from, to string, mode fs.FileMode, exclusive bool) error {
	if _, err := s.secure(from, false); err != nil {
		return err
	}
	input, err := s.root.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
	name := to
	if !exclusive {
		name += ".andeiva-next"
	}
	output, err := s.root.OpenFile(name, flags, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(output, io.LimitReader(input, limitFor(from)+1))
	if n > limitFor(from) {
		err = fail("ANDEIVA_BOOT_FILE_SIZE")
	}
	if err == nil {
		err = output.Chmod(mode)
	}
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if !exclusive {
		if err := s.root.Rename(name, to); err != nil {
			return err
		}
	}
	return s.syncDir(path.Dir(to))
}

func (s *system) lock() (*os.File, error) {
	if _, err := s.secure("var/backups", false); err != nil {
		return nil, err
	}
	if err := s.root.Mkdir(privateDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	info, err := s.secure(privateDir, false)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, fail("ANDEIVA_BOOT_BACKUP_DIRECTORY")
	}
	if _, err := s.secure(privateDir+"/lock", true); err != nil {
		return nil, err
	}
	f, err := s.root.OpenFile(privateDir+"/lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fail("ANDEIVA_BOOT_BUSY")
	}
	return f, nil
}

func (s *system) save(st *state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.atomic(journal, data, 0o600)
}

func validRecord(r record) bool {
	if !r.Present {
		return r == (record{})
	}
	decoded, err := hex.DecodeString(r.SHA256)
	return err == nil && len(decoded) == sha256.Size && r.Size >= 0 && r.Size <= maxImage && r.Mode&^0o777 == 0 && r.Mode&0o022 == 0
}

func (s *system) load() (*state, error) {
	data, err := s.readSmall(journal, false)
	if err != nil {
		return nil, err
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var st state
	if err := decoder.Decode(&st); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || st.Version != 1 || !versionPattern.MatchString(st.Kernel) || !versionPattern.MatchString(st.Alternate) || st.Kernel == st.Alternate {
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	switch st.Phase {
	case "prepared", "applying", "pending-reboot", "restoring", "restored":
	default:
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	switch st.Pending {
	case "", "dropin", "select-theme", "initramfs", "grub", "check-grub", "restore-initrd", "restore-grub", "restore-plymouth", "restore-dropin":
	default:
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	if st.Pending != "" && st.Phase != "applying" && st.Phase != "restoring" {
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	if strings.HasPrefix(st.Pending, "restore-") != (st.Phase == "restoring" && st.Pending != "") {
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	if len(st.Before) != 4 || len(st.Observed) != 4 || len(st.Context) != 4 {
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	for _, id := range []string{"dropin", "plymouth", "grub", "initrd"} {
		before, a := st.Before[id]
		observed, b := st.Observed[id]
		if !a || !b || !validRecord(before) || !validRecord(observed) {
			return nil, fail("ANDEIVA_BOOT_JOURNAL")
		}
	}
	for _, id := range []string{"defaults", "alternate-image", "alternate-kernel", "current-kernel"} {
		r, ok := st.Context[id]
		if !ok || !r.Present || !validRecord(r) {
			return nil, fail("ANDEIVA_BOOT_JOURNAL")
		}
	}
	if !st.Before["grub"].Present || !st.Before["initrd"].Present || st.Before["dropin"].Present {
		return nil, fail("ANDEIVA_BOOT_JOURNAL")
	}
	return &st, nil
}

func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 3 {
		return fail("ANDEIVA_BOOT_JOURNAL")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); ok {
		if delimiter != '{' {
			return fail("ANDEIVA_BOOT_JOURNAL")
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || name != strings.ToLower(name) || seen[name] || len(seen) > 16 {
				return fail("ANDEIVA_BOOT_JOURNAL")
			}
			seen[name] = true
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return nil
}

func (s *system) preflight() (machine, error) {
	m, err := s.probe()
	if err != nil {
		return m, err
	}
	if !versionPattern.MatchString(m.Kernel) || !versionPattern.MatchString(m.Alternate) || m.Kernel == m.Alternate {
		return m, fail("ANDEIVA_BOOT_KERNELS")
	}
	initrd, err := target("initrd", m.Kernel)
	if err != nil {
		return m, err
	}
	r, err := s.digest(initrd, false)
	if err != nil {
		return m, err
	}
	if r.Size < 0 || r.Size > maxImage {
		return m, fail("ANDEIVA_BOOT_FILE_SIZE")
	}
	required := uint64(r.Size)*2 + (512 << 20)
	if m.Free < required || m.Inodes < 4096 {
		return m, fail("ANDEIVA_BOOT_CAPACITY")
	}
	for _, name := range []string{"usr/share/grub/themes/andeiva/andeiva-logo.png", "usr/share/plymouth/themes/andeiva/andeiva-logo.png"} {
		r, err := s.digest(name, false)
		if err != nil || r.SHA256 != logoHash {
			return m, fail("ANDEIVA_BOOT_LOGO")
		}
	}
	for _, name := range []string{"etc/default/grub.d", "etc/plymouth", "boot/grub"} {
		info, err := s.secure(name, false)
		if err != nil || !info.IsDir() {
			return m, fail("ANDEIVA_BOOT_DIRECTORY")
		}
	}
	return m, nil
}

func (s *system) verifyContext(st *state) error {
	for id, want := range st.Context {
		kernel := st.Kernel
		if strings.HasPrefix(id, "alternate-") {
			kernel = st.Alternate
		}
		name, err := target(id, kernel)
		if err != nil {
			return err
		}
		got, err := s.digest(name, false)
		if err != nil || got != want {
			return fail("ANDEIVA_BOOT_CONTEXT_DRIFT")
		}
	}
	return nil
}

func (s *system) verifyBackups(st *state) error {
	for id, want := range st.Before {
		if !want.Present {
			continue
		}
		got, err := s.digest(privateDir+"/"+id+".original", false)
		if err != nil || got.Size != want.Size || got.SHA256 != want.SHA256 || got.Mode != 0o600 {
			return fail("ANDEIVA_BOOT_BACKUP_INTEGRITY")
		}
	}
	return nil
}

func (s *system) verifyLive(st *state) error {
	for id, want := range st.Observed {
		name, err := target(id, st.Kernel)
		if err != nil {
			return err
		}
		got, err := s.digest(name, true)
		if err != nil || got != want {
			return fail("ANDEIVA_BOOT_LIVE_DRIFT")
		}
	}
	return nil
}

func (s *system) prepare(ack bool) error {
	if !ack {
		return fail("ANDEIVA_BOOT_RECOVERY_ATTESTATION_REQUIRED")
	}
	m, err := s.preflight()
	if err != nil {
		return err
	}
	if _, err := s.secure(journal, true); err != nil {
		return err
	}
	if _, err := s.root.Lstat(journal); err == nil {
		st, err := s.load()
		if err != nil {
			return err
		}
		if st.Phase != "prepared" && st.Phase != "restored" || st.Kernel != m.Kernel || st.Alternate != m.Alternate {
			return fail("ANDEIVA_BOOT_ALREADY_PREPARED")
		}
		if err := errors.Join(s.verifyBackups(st), s.verifyContext(st), s.verifyLive(st)); err != nil {
			return err
		}
		if st.Phase == "restored" {
			for id, before := range st.Before {
				if st.Observed[id] != before {
					return fail("ANDEIVA_BOOT_NOT_RESTORED")
				}
			}
			st.Phase = "prepared"
			return s.save(st)
		}
		return nil
	}
	st := &state{Version: 1, Kernel: m.Kernel, Alternate: m.Alternate, Phase: "prepared", Before: map[string]record{}, Observed: map[string]record{}, Context: map[string]record{}}
	for _, id := range []string{"dropin", "plymouth", "grub", "initrd"} {
		name, err := target(id, m.Kernel)
		if err != nil {
			return err
		}
		r, err := s.digest(name, id == "dropin" || id == "plymouth")
		if err != nil {
			return err
		}
		if id == "dropin" && r.Present {
			return fail("ANDEIVA_BOOT_DROPIN_EXISTS")
		}
		st.Before[id], st.Observed[id] = r, r
		if r.Present {
			if err := s.copyFile(name, privateDir+"/"+id+".original", 0o600, true); err != nil {
				return err
			}
		}
	}
	for _, id := range []string{"defaults", "alternate-image", "alternate-kernel", "current-kernel"} {
		kernel := m.Kernel
		if strings.HasPrefix(id, "alternate-") {
			kernel = m.Alternate
		}
		name, err := target(id, kernel)
		if err != nil {
			return err
		}
		r, err := s.digest(name, false)
		if err != nil {
			return err
		}
		st.Context[id] = r
	}
	if err := s.verifyBackups(st); err != nil {
		return err
	}
	return s.save(st)
}

func (s *system) observe(st *state, touched string) error {
	for id, previous := range st.Observed {
		name, err := target(id, st.Kernel)
		if err != nil {
			return err
		}
		r, err := s.digest(name, true)
		if err != nil {
			return err
		}
		if id != touched && r != previous {
			return fail("ANDEIVA_BOOT_UNEXPECTED_CHANGE")
		}
		if id == touched {
			st.Observed[id] = r
		}
	}
	st.Pending = ""
	return s.save(st)
}

func (s *system) apply() error {
	return s.applyMode(false)
}

func bootConfiguration(diagnostic bool) string {
	return bootConfigurationOptions(diagnostic, false)
}

func bootConfigurationOptions(diagnostic, redraw bool) string {
	if redraw {
		return strings.Replace(dropin, "systemd.show_status=error", "systemd.show_status=error plymouth.set-mode-on-redraws", 1)
	}
	if !diagnostic {
		return dropin
	}
	return strings.Replace(dropin, "systemd.show_status=error", "systemd.show_status=error plymouth.debug=stream:/dev/null plymouth.debug=file:/run/andeiva-boot-plymouth-debug.log", 1)
}

func (s *system) applyMode(diagnostic bool) error {
	return s.applyOptions(diagnostic, false)
}

func (s *system) applyOptions(diagnostic, redraw bool) error {
	if diagnostic && redraw {
		return fail("ANDEIVA_BOOT_ARGUMENT")
	}
	m, err := s.preflight()
	if err != nil {
		return err
	}
	st, err := s.load()
	if err != nil {
		return err
	}
	if st.Kernel != m.Kernel || st.Alternate != m.Alternate {
		return fail("ANDEIVA_BOOT_KERNEL_CHANGED")
	}
	if err := errors.Join(s.verifyContext(st), s.verifyBackups(st), s.verifyLive(st)); err != nil {
		return err
	}
	if st.Phase == "pending-reboot" && st.Pending == "" {
		configuration, err := s.readSmall("etc/default/grub.d/99-andeiva-branding.cfg", false)
		if err != nil || string(configuration) != bootConfigurationOptions(diagnostic, redraw) {
			return fail("ANDEIVA_BOOT_MODE_CONFLICT")
		}
		return nil
	}
	if st.Phase != "prepared" || st.Pending != "" {
		return fail("ANDEIVA_BOOT_RECOVERY_REQUIRED")
	}
	if diagnostic {
		check := s.diagnosticReady
		if s.diagnostics != nil {
			check = s.diagnostics
		}
		if err := check(); err != nil {
			return err
		}
	}
	st.Phase = "applying"
	for _, step := range []string{"dropin", "select-theme", "initramfs", "grub", "check-grub"} {
		st.Pending = step
		if err := s.save(st); err != nil {
			return err
		}
		if step == "dropin" {
			name, targetErr := target("dropin", st.Kernel)
			if targetErr != nil {
				return targetErr
			}
			err = s.atomic(name, []byte(bootConfigurationOptions(diagnostic, redraw)), 0o644)
		} else {
			err = s.run(step, st.Kernel)
		}
		touched := map[string]string{"dropin": "dropin", "select-theme": "plymouth", "initramfs": "initrd", "grub": "grub"}[step]
		observeErr := s.observe(st, touched)
		if err != nil || observeErr != nil {
			return errors.Join(err, observeErr)
		}
	}
	st.Phase = "pending-reboot"
	return s.save(st)
}

func (s *system) restore() error {
	st, err := s.load()
	if err != nil {
		return err
	}
	if err := errors.Join(s.verifyBackups(st), s.verifyContext(st), s.verifyLive(st)); err != nil {
		return err
	}
	if st.Phase == "restored" {
		return nil
	}
	st.Phase = "restoring"
	for _, id := range []string{"initrd", "grub", "plymouth", "dropin"} {
		st.Pending = "restore-" + id
		if err := s.save(st); err != nil {
			return err
		}
		name, targetErr := target(id, st.Kernel)
		if targetErr != nil {
			return targetErr
		}
		before := st.Before[id]
		if before.Present {
			err = s.copyFile(privateDir+"/"+id+".original", name, fs.FileMode(before.Mode), false)
		} else if st.Observed[id].Present {
			err = s.root.Remove(name)
			if err == nil {
				err = s.syncDir(path.Dir(name))
			}
		}
		if err != nil {
			return err
		}
		if err := s.observe(st, id); err != nil {
			return err
		}
	}
	st.Phase = "restored"
	return s.save(st)
}

type boundedOutput struct{ bytes.Buffer }

func (w *boundedOutput) Write(data []byte) (int, error) {
	length := len(data)
	remaining := (64 << 10) - w.Len()
	if remaining > len(data) {
		remaining = len(data)
	}
	if remaining > 0 {
		_, _ = w.Buffer.Write(data[:remaining])
	}
	return length, nil
}

func nativeCommand(ctx context.Context, operation, kernel string) (*exec.Cmd, error) {
	if !versionPattern.MatchString(kernel) {
		return nil, fail("ANDEIVA_BOOT_KERNEL")
	}
	var cmd *exec.Cmd
	switch operation {
	case "select-theme":
		cmd = exec.CommandContext(ctx, "/usr/sbin/plymouth-set-default-theme", "andeiva")
	case "initramfs":
		// #nosec G204 -- Fixed root-owned executable/flags; the kernel is strictly validated above, bound to uname and the protected journal, and passed as one argument without a shell.
		cmd = exec.CommandContext(ctx, "/usr/sbin/update-initramfs", "-u", "-k", kernel)
	case "grub":
		cmd = exec.CommandContext(ctx, "/usr/sbin/update-grub")
	case "check-grub":
		cmd = exec.CommandContext(ctx, "/usr/bin/grub-script-check", "/boot/grub/grub.cfg")
	default:
		return nil, fail("ANDEIVA_BOOT_OPERATION")
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "TZ=UTC"}
	return cmd, nil
}

func nativeRun(operation, kernel string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd, err := nativeCommand(ctx, operation, kernel)
	if err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	output := &boundedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ANDEIVA_BOOT_COMMAND_FAILED: %s", operation)
	}
	return nil
}

func (s *system) nativeProbe() (machine, error) {
	var result machine
	if err := s.rejectPostUpdateHooks(); err != nil {
		return result, err
	}
	release, err := s.readSmall("usr/lib/os-release", false)
	if err != nil || !bytes.Contains(release, []byte("VERSION_ID=\"13\"")) || !bytes.Contains(release, []byte("ID=debian\n")) {
		return result, fail("ANDEIVA_BOOT_DEBIAN13_REQUIRED")
	}
	if _, err := s.root.Lstat("sys/firmware/efi"); !errors.Is(err, fs.ErrNotExist) {
		return result, fail("ANDEIVA_BOOT_BIOS_REQUIRED")
	}
	crypttab, err := s.readSmall("etc/crypttab", true)
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(crypttab), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return result, fail("ANDEIVA_BOOT_ENCRYPTION_UNQUALIFIED")
		}
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return result, err
	}
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			return result, fail("ANDEIVA_BOOT_KERNEL")
		}
		result.Kernel += string(rune(c))
	}
	mounts, err := readProc(true)
	if err != nil {
		return result, fail("ANDEIVA_BOOT_MOUNT_INFO")
	}
	if err := checkBootMounts(mounts); err != nil {
		return result, err
	}
	cmdline, err := readProc(false)
	if err != nil || bytes.Contains(cmdline, []byte("console=ttyS")) || bytes.Contains(cmdline, []byte("console=hvc")) {
		return result, fail("ANDEIVA_BOOT_SERIAL_UNQUALIFIED")
	}
	f, err := s.root.Open("boot")
	if err != nil {
		return result, err
	}
	entries, err := f.ReadDir(128)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) >= 128 {
		return result, fail("ANDEIVA_BOOT_KERNEL_DIRECTORY")
	}
	var alternatives []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "vmlinuz-") {
			v := strings.TrimPrefix(entry.Name(), "vmlinuz-")
			if v != result.Kernel && versionPattern.MatchString(v) {
				alternatives = append(alternatives, v)
			}
		}
	}
	if len(alternatives) != 1 {
		return result, fail("ANDEIVA_BOOT_ALTERNATIVE_KERNEL_REQUIRED")
	}
	sort.Strings(alternatives)
	result.Alternate = alternatives[0]
	for _, name := range []string{"usr/sbin/plymouth-set-default-theme", "usr/sbin/update-initramfs", "usr/sbin/update-grub", "usr/bin/grub-script-check", "usr/share/plymouth/themes/andeiva/andeiva.plymouth", "usr/share/plymouth/themes/andeiva/andeiva.script", "usr/share/grub/themes/andeiva/theme.txt"} {
		info, err := s.secure(name, false)
		if err != nil || !info.Mode().IsRegular() || strings.HasPrefix(name, "usr/sbin/") && info.Mode().Perm()&0o111 == 0 || name == "usr/bin/grub-script-check" && info.Mode().Perm()&0o111 == 0 {
			return result, fail("ANDEIVA_BOOT_PREREQUISITE")
		}
	}
	var capacity syscall.Statfs_t
	if err := syscall.Statfs("/", &capacity); err != nil {
		return result, err
	}
	result.Free, err = availableBytes(capacity)
	if err != nil {
		return result, err
	}
	result.Inodes = capacity.Ffree
	return result, nil
}

// Device names differ between physical disks and virtual storage controllers.
// Qualification is based on filesystem and mount layout, never a device label.
func checkBootMounts(mounts []byte) error {
	rootFound := false
	for _, line := range strings.Split(string(mounts), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, " - ")
		if len(fields) != 2 {
			return fail("ANDEIVA_BOOT_MOUNT_INFO")
		}
		left, right := strings.Fields(fields[0]), strings.Fields(fields[1])
		if len(left) < 6 || len(right) < 3 {
			return fail("ANDEIVA_BOOT_MOUNT_INFO")
		}
		if left[4] == "/" {
			if rootFound || right[0] != "ext4" || !strings.Contains(","+left[5]+",", ",rw,") {
				return fail("ANDEIVA_BOOT_LAYOUT_UNQUALIFIED")
			}
			rootFound = true
		}
		for _, owned := range []string{"/boot", "/etc", "/usr", "/var/backups"} {
			if left[4] == owned || strings.HasPrefix(left[4], owned+"/") || left[4] == "/var" {
				return fail("ANDEIVA_BOOT_LAYOUT_UNQUALIFIED")
			}
		}
	}
	if !rootFound {
		return fail("ANDEIVA_BOOT_LAYOUT_UNQUALIFIED")
	}
	return nil
}

func availableBytes(capacity syscall.Statfs_t) (uint64, error) {
	if capacity.Type != 0xef53 {
		return 0, fail("ANDEIVA_BOOT_LAYOUT_UNQUALIFIED")
	}
	return filesystemFreeBytes(capacity)
}

func filesystemFreeBytes(capacity syscall.Statfs_t) (uint64, error) {
	if capacity.Bsize <= 0 || capacity.Frsize <= 0 {
		return 0, fail("ANDEIVA_BOOT_CAPACITY")
	}
	// statfs block counts use the fundamental allocation unit, not the I/O size.
	blockSize := uint64(capacity.Frsize)
	if capacity.Bavail > ^uint64(0)/blockSize {
		return 0, fail("ANDEIVA_BOOT_CAPACITY")
	}
	return capacity.Bavail * blockSize, nil
}

func (s *system) checkDebugDefaults() error {
	defaults, err := s.readSmall("etc/default/grub", false)
	if err != nil {
		return err
	}
	if bytes.Contains(defaults, []byte("plymouth.debug")) {
		return fail("ANDEIVA_BOOT_EXISTING_DEBUG")
	}
	dir, err := s.root.Open("etc/default/grub.d")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(65)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 64 {
		return fail("ANDEIVA_BOOT_DEFAULTS_DIRECTORY")
	}
	for _, entry := range entries {
		if entry.Name() == "99-andeiva-branding.cfg" || !strings.HasSuffix(entry.Name(), ".cfg") {
			continue
		}
		content, err := s.readSmall("etc/default/grub.d/"+entry.Name(), false)
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte("plymouth.debug")) {
			return fail("ANDEIVA_BOOT_EXISTING_DEBUG")
		}
	}
	return nil
}

func (s *system) diagnosticReady() error {
	if err := s.checkDebugDefaults(); err != nil {
		return err
	}
	if _, err := s.secure("run", false); err != nil {
		return err
	}
	if _, err := s.root.Lstat("run/andeiva-boot-plymouth-debug.log"); !errors.Is(err, fs.ErrNotExist) {
		return fail("ANDEIVA_BOOT_DEBUG_LOG_EXISTS")
	}
	if _, err := s.secure("dev", false); err != nil {
		return err
	}
	info, err := s.root.Lstat("dev/null")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != s.owner || info.Mode()&fs.ModeCharDevice == 0 || info.Mode()&fs.ModeSymlink != 0 || stat.Rdev != 0x103 {
		return fail("ANDEIVA_BOOT_NULL_DEVICE")
	}
	var capacity syscall.Statfs_t
	if err := syscall.Statfs("/run", &capacity); err != nil {
		return err
	}
	free, err := filesystemFreeBytes(capacity)
	if err != nil || capacity.Type != 0x01021994 || free < 2<<20 || capacity.Ffree < 2 {
		return fail("ANDEIVA_BOOT_DIAGNOSTIC_CAPACITY")
	}
	return nil
}

func (s *system) rejectPostUpdateHooks() error {
	if _, err := s.secure("etc/initramfs", true); err != nil {
		return err
	}
	if _, err := s.root.Lstat("etc/initramfs/post-update.d"); !errors.Is(err, fs.ErrNotExist) {
		return fail("ANDEIVA_BOOT_POST_UPDATE_HOOKS_UNQUALIFIED")
	}
	return nil
}

func readProc(mounts bool) ([]byte, error) {
	var f *os.File
	var err error
	if mounts {
		f, err = os.Open("/proc/self/mountinfo")
	} else {
		f, err = os.Open("/proc/cmdline")
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, fail("ANDEIVA_BOOT_PROC_SIZE")
	}
	return data, err
}

func main() {
	if os.Geteuid() != 0 || len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "ANDEIVA_BOOT_LOCAL_ROOT_REQUIRED")
		os.Exit(1)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ANDEIVA_BOOT_ROOT_UNAVAILABLE")
		os.Exit(1)
	}
	defer func() { _ = root.Close() }()
	s := &system{root: root, owner: 0, run: nativeRun}
	s.probe = s.nativeProbe
	operation := os.Args[1]
	ack := len(os.Args) == 3 && os.Args[2] == "--recovery-verified" && operation == "prepare"
	diagnostic := len(os.Args) == 3 && os.Args[2] == "--diagnostic-boot" && operation == "apply"
	redraw := len(os.Args) == 3 && os.Args[2] == "--redraw-compatibility" && operation == "apply"
	if len(os.Args) == 3 && !ack && !diagnostic && !redraw {
		err = fail("ANDEIVA_BOOT_ARGUMENT")
	} else if operation == "preflight" {
		_, err = s.preflight()
	} else {
		lock, lockErr := s.lock()
		if lockErr != nil {
			err = lockErr
		} else {
			defer func() { _ = lock.Close() }()
			switch operation {
			case "prepare":
				err = s.prepare(ack)
			case "apply":
				err = s.applyOptions(diagnostic, redraw)
			case "restore":
				err = s.restore()
			case "status":
				var st *state
				st, err = s.load()
				if err == nil {
					err = json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": st.Phase, "pending": st.Pending})
				}
			default:
				err = fail("ANDEIVA_BOOT_OPERATION")
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
