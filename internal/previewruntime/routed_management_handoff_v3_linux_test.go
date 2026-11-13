//go:build linux

package previewruntime

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedManagementHandoffV3RequiresExplicitSocket(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "andeiva-management-v3")
	if resources, err := openRoutedDeploymentWithManagementV3(context.Background(), applianceConfigFixtureV3(), nil); err == nil || resources != nil {
		t.Fatal("missing named management descriptor fell back to activation environment")
	}
	if err := runRoutedSupervisorWithManagementV3(context.Background(), applianceConfigFixtureV3(), nil); err == nil {
		t.Fatal("supervisor accepted missing named descriptor")
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		t.Fatal("rejected explicit handoff consumed activation environment")
	}
}

func TestRoutedManagementHandoffV3RejectsFilesWithoutReading(t *testing.T) {
	c := applianceConfigFixtureV3()
	if file, err := duplicateRoutedManagementV3(c, nil); err == nil || file != nil {
		t.Fatal("nil descriptor accepted")
	}
	dir := t.TempDir()
	for _, name := range []string{"regular", "fifo"} {
		path := filepath.Join(dir, name)
		if name == "fifo" {
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		input, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if duplicate, err := duplicateRoutedManagementV3(c, input); err == nil || duplicate != nil {
			t.Fatal("non-socket descriptor accepted")
		}
		if _, err := input.Stat(); err != nil {
			t.Fatal("rejection consumed caller descriptor", err)
		}
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRoutedManagementHandoffNativeV3(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_MANAGEMENT_HANDOFF_V3") != "1" {
		t.Skip("explicit root Debian loopback socket qualification")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root laboratory only")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || len(release) > 16384 || !strings.Contains(string(release), "ID=debian\n") || !strings.Contains(string(release), "VERSION_ID=\"13\"\n") {
		t.Fatal("Debian13 required")
	}
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	file, err := tcp.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.SetsockoptString(int(file.Fd()), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"); err != nil {
		t.Fatal(err)
	}
	c := applianceConfigFixtureV3()
	c.ListenAddress, c.Interface, c.AllowedCIDR = tcp.Addr().String(), "lo", "127.0.0.0/8"
	duplicate, err := duplicateRoutedManagementV3(c, file)
	if err != nil {
		t.Fatal(err)
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	after, err := duplicate.Stat()
	if err != nil || !os.SameFile(before, after) || duplicate.Fd() == file.Fd() {
		t.Fatal("handoff did not retain the exact socket")
	}
	flags, err := unix.FcntlInt(duplicate.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("management duplicate lacks CLOEXEC")
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if validateRoutedManagementV3(file, c) != nil {
		t.Fatal("handoff closed caller's socket")
	}
	address := netip.MustParseAddrPort(c.ListenAddress)
	port := address.Port() - 1
	if port == 0 {
		port = 1
	}
	c.ListenAddress = netip.AddrPortFrom(address.Addr(), port).String()
	if copy, err := duplicateRoutedManagementV3(c, file); err == nil || copy != nil {
		t.Fatal("wrong management endpoint accepted")
	}
	t.Log("exact device-bound loopback socket retained with CLOEXEC and caller ownership; no activation consumer or external LAN qualification")
}
