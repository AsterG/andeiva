//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const currentTestKernel = "6.12.116+deb13-amd64"
const alternateTestKernel = "6.12.107+deb13-amd64"

func fixture(t *testing.T) *system {
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
	t.Cleanup(func() { _ = lock.Close() })
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
	if err != nil || !strings.Contains(string(configuration), `GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} quiet splash loglevel=3 systemd.show_status=auto"`) {
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
