//go:build linux

package dhcpclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Only the reviewed native harness sets this opt-in inside disposable namespaces
// and private mounts. This test must never be run privileged in WSL.
func TestNativeDHCPCDOwner(t *testing.T) {
	if os.Getenv("ANDEIVA_DHCP_NATIVE") != "1" {
		t.Skip("requires isolated Debian harness")
	}
	hostNet := os.NewFile(3, "host-net")
	defer hostNet.Close()
	hostMount := os.NewFile(4, "host-mount")
	defer hostMount.Close()
	iface, err := net.InterfaceByName("wan0")
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{HostNetwork: hostNet, HostMount: hostMount, Interface: iface.Name, Index: iface.Index, HardwareAddress: iface.HardwareAddr.String()}
	if err := verifyScope(scope); err != nil {
		t.Fatal("isolated scope", err)
	}
	before := nativeBaseline(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := StartIsolated(ctx, scope)
	if err != nil {
		t.Fatal("start", err)
	}
	defer c.Stop()
	first := awaitLease(t, c, 0, 35*time.Second)
	t.Logf("bound: owner=%s epoch=%d reason=%s", c.PID(), first.Epoch, first.Event.Reason)
	if _, err := StartIsolated(ctx, scope); !errors.Is(err, ErrScope) {
		t.Fatal("second owner accepted", err)
	}
	if err := c.Rebind(); err != nil {
		t.Fatal("rebind", err)
	}
	renewed := awaitLease(t, c, first.Epoch, 35*time.Second)
	t.Logf("renewed: epoch=%d reason=%s", renewed.Epoch, renewed.Event.Reason)
	if !bytes.Equal(before, nativeBaseline(t)) {
		t.Fatal("acquisition configured baseline")
	}
	oldPID := c.pid
	c.Stop()
	if _, err := c.Current(); err == nil {
		t.Fatal("stopped owner returned lease")
	}
	c, err = StartIsolated(ctx, scope)
	if err != nil {
		t.Fatal("restart", err)
	}
	defer c.Stop()
	if c.pid == oldPID {
		t.Fatal("owner incarnation did not change")
	}
	restarted := awaitLease(t, c, 0, 35*time.Second)
	t.Logf("restarted: owner=%s reason=%s", c.PID(), restarted.Event.Reason)
	// The server PID is a harness-owned retained child, not an installed service.
	pid, err := strconv.Atoi(os.Getenv("ANDEIVA_DHCP_SERVER_PID"))
	if err != nil || pid <= 1 {
		t.Fatal("server identity")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(130 * time.Second)
	for {
		_, err = c.Current()
		if errors.Is(err, ErrUnavailable) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease did not expire")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("expired without server; no stale lease returned")
	c.Stop()
	if !bytes.Equal(before, nativeBaseline(t)) {
		t.Fatal("stop/expiry altered nonempty baseline")
	}
	// Restart without a server must not authorize the persisted lease file.
	c, err = StartIsolated(ctx, scope)
	if err != nil {
		t.Fatal("offline restart", err)
	}
	defer c.Stop()
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		if _, err := c.Current(); err == nil {
			t.Fatal("offline restart revived lease")
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.Stop()
	if !bytes.Equal(before, nativeBaseline(t)) {
		t.Fatal("rollback baseline differs")
	}
}

func awaitLease(t *testing.T, c *Client, after uint64, limit time.Duration) Lease {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if l, err := c.Current(); err == nil && l.Epoch > after {
			return l
		}
		select {
		case <-c.done:
			t.Fatal("dhcpcd exited before acquisition")
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("lease acquisition deadline")
	return Lease{}
}

func nativeBaseline(t *testing.T) []byte {
	t.Helper()
	var b []byte
	for _, args := range [][]string{{"-j", "-4", "address", "show"}, {"-j", "-4", "route", "show", "table", "all"}} {
		out, err := exec.Command("/usr/bin/ip", args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, out...)
	}
	if !bytes.Contains(b, []byte("198.19.0.1")) {
		t.Fatal("nonempty LAN baseline absent")
	}
	return b
}
