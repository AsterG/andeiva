//go:build linux

package previewruntime

import (
	"errors"
	"flag"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

var nativeBootIDMount = flag.Bool("native-routed-boot-id-mount", false, "test BootID with real mounts in private Linux mount namespaces")

// Reproduce the packaged unit mount in a private mount namespace.
func TestRoutedKernelBootIDReadOnlyMountNative(t *testing.T) {
	if !*nativeBootIDMount {
		t.Skip("requires explicit private-mount laboratory")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	type step struct {
		name string
		run  func() error
	}
	const kernel = "/proc/sys/kernel"
	const uuid = "/proc/sys/kernel/random/uuid"
	bind := func(src, dst string) error { return unix.Mount(src, dst, "", unix.MS_BIND, "") }
	readonly := func(dst string) error {
		return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	}
	accept := func() error {
		want, err := os.ReadFile(routedKernelBootIDPath)
		if err != nil {
			return err
		}
		got, err := readRoutedKernelBootID()
		if err != nil || got+"\n" != string(want) {
			return errors.New("genuine identity rejected: " + got)
		}
		return nil
	}
	reject := func() error {
		if id, err := readRoutedKernelBootID(); id != "" || !errors.Is(err, ErrIdentity) {
			return errors.New("identity accepted: " + id)
		}
		return nil
	}
	scenarios := map[string][]step{
		"read-only kernel subtree is accepted": {
			{"bind", func() error { return bind(kernel, kernel) }}, {"ro", func() error { return readonly(kernel) }}, {"accept", accept},
		},
		"writable kernel subtree is rejected": {
			{"bind", func() error { return bind(kernel, kernel) }}, {"reject", reject},
		},
		"leaf overlay above the read-only subtree is rejected": {
			{"bind", func() error { return bind(kernel, kernel) }}, {"ro", func() error { return readonly(kernel) }},
			{"overlay", func() error { return bind(routedKernelBootIDPath, routedKernelBootIDPath) }}, {"reject", reject},
		},
		"generator overlay above the read-only subtree is rejected": {
			{"bind", func() error { return bind(kernel, kernel) }}, {"ro", func() error { return readonly(kernel) }},
			{"overlay", func() error { return bind(uuid, routedKernelBootIDPath) }}, {"reject", reject},
		},
		"read-only random subtree is rejected": {
			{"bind", func() error { return bind(kernel+"/random", kernel+"/random") }}, {"ro", func() error { return readonly(kernel + "/random") }}, {"reject", reject},
		},
		"read-only whole sys subtree is rejected": {
			{"bind", func() error { return bind("/proc/sys", "/proc/sys") }}, {"ro", func() error { return readonly("/proc/sys") }}, {"reject", reject},
		},
		"second procfs instance mounted over proc is self-consistent": {
			{"mount", func() error { return unix.Mount("proc", "/proc", "proc", 0, "") }}, {"accept", accept},
		},
	}
	for name, steps := range scenarios {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			go func() {
				runtime.LockOSThread() // discarded with its private mount namespace
				if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
					result <- err
					return
				}
				if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
					result <- err
					return
				}
				for _, s := range steps {
					if err := s.run(); err != nil {
						result <- errors.New(s.name + ": " + err.Error())
						return
					}
				}
				result <- nil
			}()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
