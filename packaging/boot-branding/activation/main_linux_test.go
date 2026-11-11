//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const currentTestKernel = "6.12.116+deb13-amd64"
const alternateTestKernel = "6.12.107+deb13-amd64"

func TestBootLayoutUsesCapabilitiesInsteadOfDeviceNames(t *testing.T) {
	for _, device := range []string{"/dev/sda1", "/dev/vda1", "/dev/nvme0n1p2", "/dev/mapper/system-root", "/dev/root"} {
		t.Run(device, func(t *testing.T) {
			mounts := "29 1 8:1 / / rw,relatime - ext4 " + device + " rw\n30 29 0:10 / /run rw - tmpfs tmpfs rw\n"
			if err := checkBootMounts([]byte(mounts)); err != nil {
				t.Fatalf("equivalent ext4 layout rejected: %v", err)
			}
		})
	}
	root := "29 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
	for name, mounts := range map[string]string{
		"missing-root":   "",
		"malformed":      "not mountinfo\n",
		"read-only":      strings.Replace(root, "rw,relatime", "ro,relatime", 1),
		"overlay":        strings.Replace(root, "ext4", "overlay", 1),
		"duplicate-root": root + root,
		"separate-boot":  root + "30 29 8:2 / /boot rw - ext4 /dev/other rw\n",
		"boot-submount":  root + "30 29 8:2 / /boot/grub rw - ext4 /dev/other rw\n",
		"separate-var":   root + "30 29 8:2 / /var rw - ext4 /dev/other rw\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkBootMounts([]byte(mounts)); err == nil {
				t.Fatal("unqualified or malformed layout accepted")
			}
		})
	}
}

func TestCapacityUsesReportedFilesystemBlockSize(t *testing.T) {
	for _, blockSize := range []int64{1024, 4096, 65536} {
		got, err := availableBytes(syscall.Statfs_t{Type: 0xef53, Bsize: blockSize, Frsize: blockSize, Bavail: 42})
		if err != nil || got != uint64(blockSize)*42 {
			t.Fatalf("block size %d: bytes=%d err=%v", blockSize, got, err)
		}
	}
	if got, err := availableBytes(syscall.Statfs_t{Type: 0xef53, Bsize: 65536, Frsize: 4096, Bavail: 42}); err != nil || got != 42*4096 {
		t.Fatalf("I/O size used as allocation unit: bytes=%d err=%v", got, err)
	}
	for _, capacity := range []syscall.Statfs_t{
		{Type: 0xef53, Bsize: 0, Frsize: 4096, Bavail: 1},
		{Type: 0xef53, Bsize: -1, Frsize: 4096, Bavail: 1},
		{Type: 0xef53, Bsize: 4096, Frsize: 0, Bavail: 1},
		{Type: 0xef53, Bsize: 4096, Frsize: -1, Bavail: 1},
		{Type: 0xef53, Bsize: 65536, Frsize: 4096, Bavail: ^uint64(0)},
		{Type: 0x794c7630, Bsize: 4096, Frsize: 4096, Bavail: 1},
	} {
		if _, err := availableBytes(capacity); err == nil {
			t.Fatal("invalid or overflowing filesystem capacity accepted")
		}
	}
}

func TestOfflineMarkerSurvivesLockOwnerExit(t *testing.T) {
	s := fixtureWithLock(t, false)
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.root.Mkdir("var/backups/andeiva-boot-offline", 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestOfflineCrashHelper$")
	command.Env = append(os.Environ(), "ANDEIVA_TEST_OFFLINE_CRASH=1", "ANDEIVA_TEST_OFFLINE_ROOT="+s.root.Name())
	output, err := command.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 73 {
		t.Fatalf("unexpected simulated installer exit: %v: %s", err, output)
	}
	lock, err := s.lock()
	if err != nil {
		t.Fatalf("dead installer retained live lock: %v", err)
	}
	defer func() { _ = lock.Close() }()
	if err := s.apply(); err == nil || err.Error() != "ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING" {
		t.Fatalf("lost lock allowed activation while marker remains: %v", err)
	}
	if err := s.restore(); err == nil || err.Error() != "ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING" {
		t.Fatalf("lost lock allowed restoration while marker remains: %v", err)
	}
}

func TestOfflineCrashHelper(t *testing.T) {
	if os.Getenv("ANDEIVA_TEST_OFFLINE_CRASH") != "1" {
		return
	}
	root, err := os.OpenRoot(os.Getenv("ANDEIVA_TEST_OFFLINE_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	s := &system{root: root, owner: uint32(os.Geteuid())}
	lock, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	marker, err := root.OpenFile("var/backups/andeiva-boot-offline/install-pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := marker.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := marker.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.syncDir("var/backups/andeiva-boot-offline"); err != nil {
		t.Fatal(err)
	}
	// Exit without deferred cleanup, as with a lost installer process. This is
	// process-interruption evidence, not a physical power-loss test.
	os.Exit(73)
}

func TestOfflinePendingInstallBlocksBootMutations(t *testing.T) {
	for _, mutation := range []string{"prepare", "apply", "restore"} {
		t.Run(mutation, func(t *testing.T) {
			s := fixture(t)
			if err := s.prepare(true); err != nil {
				t.Fatal(err)
			}
			before, err := s.root.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			const directory = "var/backups/andeiva-boot-offline"
			if err := s.root.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			marker, err := s.root.Create(directory + "/install-pending")
			if err != nil {
				t.Fatal(err)
			}
			if err := marker.Close(); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "prepare":
				err = s.prepare(true)
			case "apply":
				err = s.apply()
			case "restore":
				err = s.restore()
			}
			if err == nil || err.Error() != "ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING" {
				t.Fatalf("pending install did not block %s: %v", mutation, err)
			}
			after, err := s.root.ReadFile(journal)
			if err != nil || string(after) != string(before) {
				t.Fatalf("blocked mutation changed journal: %v", err)
			}
			st, err := s.load()
			if err != nil {
				t.Fatalf("read-only state unavailable: %v", err)
			}
			if err := s.verifyLive(st); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOfflineGuardRejectsUnsafeAndAmbiguousPaths(t *testing.T) {
	for _, name := range []string{"marker-link", "parent-link", "writable-directory", "marker-directory"} {
		t.Run(name, func(t *testing.T) {
			s := fixture(t)
			const directory = "var/backups/andeiva-boot-offline"
			if name == "parent-link" {
				if err := s.root.Symlink(".", directory); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.root.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "marker-link":
					if err := s.root.Symlink("absent", directory+"/install-pending"); err != nil {
						t.Fatal(err)
					}
				case "writable-directory":
					if err := s.root.Chmod(directory, 0o777); err != nil {
						t.Fatal(err)
					}
				case "marker-directory":
					if err := s.root.Mkdir(directory+"/install-pending", 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := s.checkOfflineInstallPending(); err == nil {
				t.Fatal("unsafe or ambiguous install state accepted")
			}
		})
	}
}

func TestRedrawCompatibilityIsExplicitReversibleAndModeBound(t *testing.T) {
	s := fixture(t)
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.applyOptions(true, true); err == nil {
		t.Fatal("combined diagnostic and compatibility modes accepted")
	}
	st, err := s.load()
	if err != nil || st.Phase != "prepared" || st.Pending != "" {
		t.Fatalf("invalid mode changed journal: %+v %v", st, err)
	}
	if err := s.verifyLive(st); err != nil {
		t.Fatal(err)
	}
	if err := s.applyOptions(false, true); err != nil {
		t.Fatal(err)
	}
	configuration, err := s.root.ReadFile("etc/default/grub.d/99-andeiva-branding.cfg")
	want := strings.Replace(dropin, "systemd.show_status=error", "systemd.show_status=error plymouth.set-mode-on-redraws", 1)
	if err != nil || string(configuration) != want || strings.Contains(string(configuration), "plymouth.debug") {
		t.Fatalf("unexpected compatibility configuration: %v", err)
	}
	if err := s.applyOptions(false, true); err != nil {
		t.Fatalf("idempotent compatibility apply: %v", err)
	}
	for _, diagnostic := range []bool{false, true} {
		if err := s.applyMode(diagnostic); err == nil {
			t.Fatalf("different mode accepted pending compatibility configuration: diagnostic=%v", diagnostic)
		}
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	configuration, err = s.root.ReadFile("etc/default/grub.d/99-andeiva-branding.cfg")
	if err != nil || string(configuration) != dropin {
		t.Fatalf("default retained compatibility mode: %v", err)
	}
	if err := s.applyOptions(false, true); err == nil {
		t.Fatal("compatibility mode accepted pending default configuration")
	}
}

func TestDiagnosticBootModeIsExplicitAndReversible(t *testing.T) {
	s := fixture(t)
	checks := 0
	s.diagnostics = func() error { checks++; return nil }
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.applyMode(true); err != nil {
		t.Fatal(err)
	}
	configuration, err := s.root.ReadFile("etc/default/grub.d/99-andeiva-branding.cfg")
	if err != nil || string(configuration) != bootConfiguration(true) {
		t.Fatalf("diagnostic configuration: %v", err)
	}
	if strings.Count(string(configuration), "plymouth.debug=") != 2 ||
		!strings.Contains(string(configuration), "plymouth.debug=stream:/dev/null plymouth.debug=file:/run/andeiva-boot-plymouth-debug.log") ||
		strings.Contains(string(configuration), "/dev/kmsg") || strings.Contains(string(configuration), "GRUB_CMDLINE_LINUX=") {
		t.Fatal("diagnostic output is not restricted to fixed normal-boot destinations")
	}
	if err := s.apply(); err == nil {
		t.Fatal("normal apply accepted pending diagnostic configuration")
	}
	if err := s.applyMode(true); err != nil || checks != 1 {
		t.Fatalf("idempotent diagnostic apply: %v checks=%d", err, checks)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	configuration, err = s.root.ReadFile("etc/default/grub.d/99-andeiva-branding.cfg")
	if err != nil || string(configuration) != dropin || strings.Contains(string(configuration), "plymouth.debug") {
		t.Fatal("normal configuration retained diagnostic parameters")
	}
	if err := s.applyMode(true); err == nil {
		t.Fatal("diagnostic apply accepted pending normal configuration")
	}
}

func TestDiagnosticRefusalHasNoBootEffects(t *testing.T) {
	s := fixture(t)
	s.diagnostics = func() error { return errors.New("diagnostic storage unavailable") }
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.applyMode(true); err == nil {
		t.Fatal("diagnostic readiness failure ignored")
	}
	st, err := s.load()
	if err != nil || st.Phase != "prepared" || st.Pending != "" {
		t.Fatalf("state changed after refusal: %+v %v", st, err)
	}
	if err := s.verifyLive(st); err != nil {
		t.Fatal(err)
	}
}

func TestExistingDebugDefaultsAreRejected(t *testing.T) {
	s := fixture(t)
	if err := s.checkDebugDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := s.root.WriteFile("etc/default/grub.d/other.cfg", []byte("GRUB_CMDLINE_LINUX_DEFAULT=\"plymouth.debug=stream:/tmp/other\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.checkDebugDefaults(); err == nil {
		t.Fatal("conflicting debug drop-in accepted")
	}
	if err := s.root.Remove("etc/default/grub.d/other.cfg"); err != nil {
		t.Fatal(err)
	}
	if err := s.root.WriteFile("etc/default/grub", []byte("GRUB_CMDLINE_LINUX_DEFAULT=\"plymouth.debug=file:/tmp/other\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.checkDebugDefaults(); err == nil {
		t.Fatal("conflicting debug defaults accepted")
	}
}

func TestDiagnosticRuntimePathsRejectExistingAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"existing-log", "log-symlink", "writable-run", "regular-null"} {
		t.Run(kind, func(t *testing.T) {
			s := fixture(t)
			if err := s.root.Mkdir("run", 0o755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "existing-log":
				if err := s.root.WriteFile("run/andeiva-boot-plymouth-debug.log", []byte("retained trace"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "log-symlink":
				if err := os.Symlink("../etc/default/grub", filepath.Join(s.root.Name(), "run/andeiva-boot-plymouth-debug.log")); err != nil {
					t.Fatal(err)
				}
			case "writable-run":
				if err := os.Chmod(filepath.Join(s.root.Name(), "run"), 0o777); err != nil {
					t.Fatal(err)
				}
			case "regular-null":
				if err := s.root.Mkdir("dev", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := s.root.WriteFile("dev/null", []byte("not a device"), 0o666); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.diagnosticReady(); err == nil {
				t.Fatal("unsafe diagnostic path accepted")
			}
		})
	}
}

func fixture(t *testing.T) *system {
	return fixtureWithLock(t, true)
}

func fixtureWithLock(t *testing.T, retainLock bool) *system {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"boot/grub", "etc/default/grub.d", "etc/plymouth", "var/backups", "usr/share/grub/themes/andeiva", "usr/share/plymouth/themes/andeiva"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logo, err := os.ReadFile("../../../frontend/public/andeiva-logo.png")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"etc/default/grub": []byte("GRUB_TIMEOUT=5\n"), "boot/grub/grub.cfg": []byte("original grub"),
		"etc/plymouth/plymouthd.conf":                        []byte("[Daemon]\nTheme=text\n"),
		"boot/initrd.img-" + currentTestKernel:               []byte("original initrd"),
		"boot/initrd.img-" + alternateTestKernel:             []byte("alternative initrd"),
		"boot/vmlinuz-" + alternateTestKernel:                []byte("alternative kernel"),
		"boot/vmlinuz-" + currentTestKernel:                  []byte("current kernel"),
		"usr/share/grub/themes/andeiva/andeiva-logo.png":     logo,
		"usr/share/plymouth/themes/andeiva/andeiva-logo.png": logo,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &system{root: root, owner: uint32(os.Getuid())}
	s.probe = func() (machine, error) { return machine{currentTestKernel, alternateTestKernel, 2 << 30, 10000}, nil }
	s.run = func(operation, kernel string) error {
		if kernel != currentTestKernel {
			t.Fatalf("wrong kernel passed to runner: %q", kernel)
		}
		switch operation {
		case "select-theme":
			return s.atomic("etc/plymouth/plymouthd.conf", []byte("[Daemon]\nTheme=andeiva\n"), 0o644)
		case "initramfs":
			return s.atomic("boot/initrd.img-"+kernel, []byte("new initrd"), 0o644)
		case "grub":
			return s.atomic("boot/grub/grub.cfg", []byte("new grub"), 0o644)
		case "check-grub":
			return nil
		}
		t.Fatalf("unexpected command: %s", operation)
		return nil
	}
	lock, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	if retainLock {
		t.Cleanup(func() { _ = lock.Close() })
	} else if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNativeCommandContractWithoutExecution(t *testing.T) {
	cmd, err := nativeCommand(context.Background(), "initramfs", currentTestKernel)
	if err != nil || cmd.Path != "/usr/sbin/update-initramfs" || !reflect.DeepEqual(cmd.Args, []string{"/usr/sbin/update-initramfs", "-u", "-k", currentTestKernel}) {
		t.Fatalf("wrong fixed initramfs command: %v, %v", cmd, err)
	}
	if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "TZ=UTC"}) {
		t.Fatal("inherited command environment")
	}
	for _, value := range []string{"-all", "all", "../../etc/passwd", "6.12.116;false", "6.12.116\n", "$(false)"} {
		if _, err := nativeCommand(context.Background(), "initramfs", value); err == nil {
			t.Fatalf("unexpected kernel value accepted: %q", value)
		}
	}
	if _, err := nativeCommand(context.Background(), "arbitrary-command", currentTestKernel); err == nil {
		t.Fatal("unexpected operation accepted")
	}
}

func TestPrepareApplyRestoreAndIdempotence(t *testing.T) {
	s := fixture(t)
	var calls []string
	runner := s.run
	s.run = func(op, kernel string) error { calls = append(calls, op); return runner(op, kernel) }
	if err := s.prepare(false); err == nil {
		t.Fatal("missing recovery attestation accepted")
	}
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	configuration, err := s.root.ReadFile("etc/default/grub.d/99-andeiva-branding.cfg")
	if err != nil || !strings.Contains(string(configuration), `GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} quiet splash loglevel=3 systemd.show_status=error"`) {
		t.Fatalf("normal-boot console policy missing: %v", err)
	}
	if strings.Contains(string(configuration), "GRUB_CMDLINE_LINUX=") || !strings.Contains(string(configuration), "GRUB_TIMEOUT=5\nGRUB_DISABLE_RECOVERY=false\n") {
		t.Fatal("normal-boot policy must not replace recovery arguments or hide recovery")
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"select-theme", "initramfs", "grub", "check-grub"}) {
		t.Fatal(calls)
	}
	st, _ := s.load()
	if st.Phase != "pending-reboot" || st.Pending != "" {
		t.Fatal(st)
	}
	// Restoration from the fallback kernel must not depend on the running kernel.
	s.probe = func() (machine, error) { return machine{alternateTestKernel, currentTestKernel, 2 << 30, 10000}, nil }
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	st, _ = s.load()
	if st.Phase != "restored" || !reflect.DeepEqual(st.Before, st.Observed) {
		t.Fatal("original state not restored")
	}
	data, _ := s.root.ReadFile("boot/initrd.img-" + alternateTestKernel)
	if string(data) != "alternative initrd" {
		t.Fatal("alternative kernel image changed")
	}
}

func TestPartialCommandFailureCanRestoreObservedBytes(t *testing.T) {
	s := fixture(t)
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	runner := s.run
	s.run = func(op, kernel string) error {
		if op == "initramfs" {
			if err := s.atomic("boot/initrd.img-"+kernel, []byte("incomplete command output"), 0o644); err != nil {
				return err
			}
			return errors.New("injected command failure")
		}
		return runner(op, kernel)
	}
	if err := s.apply(); err == nil {
		t.Fatal("failed command accepted")
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedCommandAndExternalDriftRefuseOverwrite(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "external-drift", true: "interrupted-command"}[interrupted], func(t *testing.T) {
			s := fixture(t)
			if err := s.prepare(true); err != nil {
				t.Fatal(err)
			}
			if interrupted {
				s.run = func(op, kernel string) error {
					if err := s.atomic("boot/initrd.img-"+kernel, []byte("unobserved bytes"), 0o644); err != nil {
						t.Fatal(err)
					}
					panic("simulated process termination")
				}
				func() { defer func() { _ = recover() }(); _ = s.apply() }()
			} else if err := s.atomic("boot/initrd.img-"+currentTestKernel, []byte("external bytes"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := s.restore(); err == nil || !strings.Contains(err.Error(), "ANDEIVA_BOOT_LIVE_DRIFT") {
				t.Fatalf("ambiguous bytes overwritten: %v", err)
			}
		})
	}
}

func TestPreflightAndIntegrityRejections(t *testing.T) {
	for _, scenario := range []string{"capacity", "inodes", "kernel-change", "symlink", "permissions", "backup", "journal", "concurrency"} {
		t.Run(scenario, func(t *testing.T) {
			s := fixture(t)
			if err := s.prepare(true); err != nil {
				t.Fatal(err)
			}
			var err error
			switch scenario {
			case "capacity", "inodes", "kernel-change":
				s.probe = func() (machine, error) {
					m := machine{currentTestKernel, alternateTestKernel, 2 << 30, 10000}
					switch scenario {
					case "capacity":
						m.Free = 1
					case "inodes":
						m.Inodes = 1
					case "kernel-change":
						m.Kernel, m.Alternate = m.Alternate, m.Kernel
					}
					return m, nil
				}
				err = s.apply()
			case "symlink":
				if e := s.root.Remove("boot/grub/grub.cfg"); e != nil {
					t.Fatal(e)
				}
				if e := s.root.Symlink("../initrd.img-"+currentTestKernel, "boot/grub/grub.cfg"); e != nil {
					t.Fatal(e)
				}
				err = s.apply()
			case "permissions":
				if e := s.root.Chmod("boot/grub/grub.cfg", 0o666); e != nil {
					t.Fatal(e)
				}
				err = s.apply()
			case "backup":
				if e := s.atomic(privateDir+"/initrd.original", []byte("changed"), 0o600); e != nil {
					t.Fatal(e)
				}
				err = s.restore()
			case "journal":
				st, _ := s.load()
				st.Before["unexpected"] = st.Before["initrd"]
				delete(st.Before, "initrd")
				data, _ := json.Marshal(st)
				if e := s.atomic(journal, data, 0o600); e != nil {
					t.Fatal(e)
				}
				_, err = s.load()
			case "concurrency":
				second, e := s.lock()
				if second != nil {
					_ = second.Close()
				}
				err = e
			}
			if err == nil {
				t.Fatal("unsafe operation accepted")
			}
		})
	}
}

func TestJournalRejectsDuplicatesCaseAliasesAndInvalidPending(t *testing.T) {
	for _, scenario := range []string{"duplicate", "case-alias", "pending", "missing-required-original"} {
		t.Run(scenario, func(t *testing.T) {
			s := fixture(t)
			if err := s.prepare(true); err != nil {
				t.Fatal(err)
			}
			data, err := s.readSmall(journal, false)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "duplicate":
				data = []byte(strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1))
			case "case-alias":
				data = []byte(strings.Replace(string(data), `"version":1`, `"Version":1`, 1))
			case "pending":
				data = []byte(strings.Replace(string(data), `"pending":""`, `"pending":"restore-initrd"`, 1))
			case "missing-required-original":
				st, _ := s.load()
				st.Before["initrd"] = record{}
				data, _ = json.Marshal(st)
			}
			if err := s.atomic(journal, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.load(); err == nil {
				t.Fatal("malformed journal accepted")
			}
		})
	}
}

func TestCommandCannotAdoptUnrelatedTargetDrift(t *testing.T) {
	s := fixture(t)
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	runner := s.run
	s.run = func(op, kernel string) error {
		if op == "select-theme" {
			if err := s.atomic("boot/grub/grub.cfg", []byte("unexpected independent edit"), 0o644); err != nil {
				return err
			}
		}
		return runner(op, kernel)
	}
	if err := s.apply(); err == nil || !strings.Contains(err.Error(), "ANDEIVA_BOOT_UNEXPECTED_CHANGE") {
		t.Fatalf("unrelated drift adopted: %v", err)
	}
	if err := s.restore(); err == nil {
		t.Fatal("independent edit overwritten")
	}
	data, _ := s.root.ReadFile("boot/grub/grub.cfg")
	if string(data) != "unexpected independent edit" {
		t.Fatal("independent edit changed")
	}
}

func TestUnqualifiedPostUpdateDirectoryIsRejected(t *testing.T) {
	s := fixture(t)
	if err := s.rejectPostUpdateHooks(); err != nil {
		t.Fatal(err)
	}
	if err := s.root.Mkdir("etc/initramfs", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.root.Mkdir("etc/initramfs/post-update.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.rejectPostUpdateHooks(); err == nil {
		t.Fatal("unqualified hook directory accepted")
	}
}

func TestRestoredSetCanBeRearmedWithoutReplacingBackups(t *testing.T) {
	s := fixture(t)
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	backup, err := s.digest(privateDir+"/initrd.original", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(); err == nil {
		t.Fatal("restored set applied without rearming")
	}
	if err := s.prepare(false); err == nil {
		t.Fatal("rearm accepted without renewed recovery attestation")
	}
	if err := s.prepare(true); err != nil {
		t.Fatal(err)
	}
	after, err := s.digest(privateDir+"/initrd.original", false)
	if err != nil || after != backup {
		t.Fatal("original backup replaced")
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
}

func TestRearmRejectsDriftAndDifferentKernelContext(t *testing.T) {
	for _, scenario := range []string{"live", "context", "kernel", "backup", "pending", "not-original"} {
		t.Run(scenario, func(t *testing.T) {
			s := fixture(t)
			if err := s.prepare(true); err != nil {
				t.Fatal(err)
			}
			if err := s.apply(); err != nil {
				t.Fatal(err)
			}
			if err := s.restore(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "live":
				if err := s.atomic("boot/grub/grub.cfg", []byte("external edit"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "context":
				if err := s.atomic("etc/default/grub", []byte("external defaults"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "kernel":
				s.probe = func() (machine, error) { return machine{alternateTestKernel, currentTestKernel, 2 << 30, 10000}, nil }
			case "backup":
				if err := s.atomic(privateDir+"/initrd.original", []byte("changed backup"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				st, _ := s.load()
				st.Pending = "restore-initrd"
				if err := s.save(st); err != nil {
					t.Fatal(err)
				}
			case "not-original":
				if err := s.atomic("boot/grub/grub.cfg", []byte("observed nonoriginal"), 0o644); err != nil {
					t.Fatal(err)
				}
				st, _ := s.load()
				st.Observed["grub"], _ = s.digest("boot/grub/grub.cfg", false)
				if err := s.save(st); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.prepare(true); err == nil {
				t.Fatal("unsafe rearm accepted")
			}
		})
	}
}
