//go:build linux

package previewruntime

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedKernelBootIDAcceptsOnlyExactReadOnlyKernelMount(t *testing.T) {
	const mount = "64 19 0:23 /sys/kernel /proc/sys/kernel ro,nosuid,nodev,noexec,relatime - proc proc rw\n"
	if !routedProtectedKernelMountInfo(strings.NewReader(mount), 19, 64, "0:23") {
		t.Fatal("genuine read-only kernel mount rejected")
	}
	for _, fake := range []string{
		strings.Replace(mount, "64 19", "64 42", 1),
		strings.Replace(mount, "0:23", "0:42", 1),
		strings.Replace(mount, " /sys/kernel ", " /sys/kernel/random ", 1),
		strings.Replace(mount, " /proc/sys/kernel ", " /proc/sys/kernel/random/boot_id ", 1),
		strings.Replace(mount, " ro,", " rw,", 1),
		strings.Replace(mount, " - proc ", " - ext4 ", 1),
	} {
		if routedProtectedKernelMountInfo(strings.NewReader(fake), 19, 64, "0:23") {
			t.Fatal("accepted a different kernel mount", fake)
		}
	}
}

func TestRoutedKernelBootIDReadsProcfs(t *testing.T) {
	id, err := readRoutedKernelBootID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(routedKernelBootIDPath)
	if err != nil || string(raw) != id+"\n" {
		t.Fatal("boot identity differs from the running kernel", err)
	}
}

func TestRoutedKernelBootIDRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(path, []byte("12345678-1234-1234-1234-123456789abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if id, err := readRoutedProcBootID(file, 0); id != "" || !errors.Is(err, ErrIdentity) {
		t.Fatal("regular file supplied a boot identity", err)
	}
}

func routedProcRootMountForTest(t *testing.T) uint64 {
	t.Helper()
	root, err := unix.Open(routedKernelProcRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	mount, inode, ok := routedProcMountID(root)
	if !ok || inode != routedKernelProcRootIno {
		t.Fatal("procfs root is not observable")
	}
	return mount
}

// The per-read generator has the same type, mount and format as the boot
// identity. A single validated read accepts it; only agreement rejects it.
func TestRoutedKernelBootIDRejectsPerReadGenerator(t *testing.T) {
	const generator = "sys/kernel/random/uuid"
	file, err := os.Open(routedKernelProcRoot + "/" + generator)
	if err != nil {
		t.Skip("kernel does not expose the per-read generator")
	}
	defer file.Close()
	single, err := readRoutedProcBootID(file, routedProcRootMountForTest(t))
	if err != nil || !bootPattern.MatchString(single) {
		t.Fatal("generator no longer resembles a boot identity; the negative is not meaningful", err)
	}
	for range 8 {
		if id, err := readRoutedProcIdentity(generator); id != "" || !errors.Is(err, ErrIdentity) {
			t.Fatal("per-read generator supplied a boot identity", err)
		}
	}
}

func TestRoutedKernelBootIDRejectsForeignProcMount(t *testing.T) {
	file, err := os.Open(routedKernelBootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if id, err := readRoutedProcBootID(file, routedProcRootMountForTest(t)+1); id != "" || !errors.Is(err, ErrIdentity) {
		t.Fatal("identity from another mount was accepted", err)
	}
}

// A bind mount of the genuine file over the fixed name keeps the type, the
// filesystem and the stable content, and differs only in its mount identity.
func TestRoutedKernelBootIDRejectsOverlaidMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a private mount namespace")
	}
	result := make(chan error, 1)
	go func() {
		// The thread keeps the private mount namespace and is discarded on exit.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			result <- errors.Join(errRoutedBootIDTestSkip, err)
			return
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			result <- errors.Join(errRoutedBootIDTestSkip, err)
			return
		}
		if _, err := readRoutedKernelBootID(); err != nil {
			result <- errors.New("genuine identity rejected before the overlay")
			return
		}
		if err := unix.Mount(routedKernelBootIDPath, routedKernelBootIDPath, "", unix.MS_BIND, ""); err != nil {
			result <- errors.Join(errRoutedBootIDTestSkip, err)
			return
		}
		if id, err := readRoutedKernelBootID(); id != "" || !errors.Is(err, ErrIdentity) {
			result <- errors.New("overlaid boot identity was accepted")
			return
		}
		result <- nil
	}()
	if err := <-result; errors.Is(err, errRoutedBootIDTestSkip) {
		t.Skip("private mount namespace unavailable: ", err)
	} else if err != nil {
		t.Fatal(err)
	}
}

var errRoutedBootIDTestSkip = errors.New("mount namespace unavailable")
