//go:build linux

package dhcpclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
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
	if os.Getenv("ANDEIVA_DHCP_EARLY_SERVER_DEATH") == "1" {
		stopNativeServer(t)
		c, err := StartIsolated(ctx, scope)
		if err != nil {
			t.Fatal("start without server", err)
		}
		defer c.Stop()
		until := time.Now().Add(35 * time.Second)
		for time.Now().Before(until) {
			if _, err := c.Current(); err == nil {
				t.Fatal("early server death produced lease evidence")
			}
			time.Sleep(100 * time.Millisecond)
		}
		c.Stop()
		if !bytes.Equal(before, nativeBaseline(t)) {
			t.Fatal("early server death changed baseline")
		}
		t.Log("server killed before acquisition; no lease evidence; baseline preserved")
		return
	}
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
	// Acquisition-only mode deliberately leaves the WAN unconfigured. Apply
	// this fixture's confirmed lease as an explicit, reversible L3 delta before
	// testing unicast renewal. This is not an appliance adoption transaction.
	removeWAN := nativeApplyWANLease(t, scope, first)
	configured := nativeBaseline(t)
	t.Log("fixture L3 applied confirmed WAN lease; LAN baseline retained")
	if err := c.Renew(); err != nil {
		t.Fatal("renew", err)
	}
	renewed := awaitLease(t, c, first.Epoch, 35*time.Second)
	t.Logf("renewed: epoch=%d reason=%s", renewed.Epoch, renewed.Event.Reason)
	if renewed.Event.Reason != "RENEW" {
		t.Fatal("renew did not receive renewal ACK", renewed.Event.Reason)
	}
	if err := c.Rebind(); err != nil {
		t.Fatal("rebind", err)
	}
	rebound := awaitLease(t, c, renewed.Epoch, 35*time.Second)
	t.Logf("rebound: epoch=%d reason=%s", rebound.Epoch, rebound.Event.Reason)
	if !bytes.Equal(configured, nativeBaseline(t)) {
		t.Fatal("client changed explicit fixture L3 state")
	}
	oldPID := c.pid
	c.Stop()
	removeWAN()
	if !bytes.Equal(before, nativeBaseline(t)) {
		t.Fatal("WAN delta rollback changed baseline")
	}
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
	removeRestartWAN := nativeApplyWANLease(t, scope, restarted)
	stopNativeServer(t)
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
	removeRestartWAN()
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

func nativeApplyWANLease(t *testing.T, scope Scope, lease Lease) func() {
	t.Helper()
	if err := verifyScope(scope); err != nil {
		t.Fatal("L3 scope", err)
	}
	now, err := bootNow()
	if err != nil || lease.Event.validate() != nil || lease.DeadlineBootNS <= now || lease.Event.Interface != scope.Interface || scope.Interface != "wan0" || lease.Event.Address != "198.18.1.10/24" || lease.Event.Gateway != "198.18.1.1" {
		t.Fatal("L3 fixture lease binding")
	}
	if len(nativeWANAddresses(t, scope)) != 0 {
		t.Fatal("fixture WAN was not empty")
	}
	removed := false
	remove := func() {
		if removed {
			return
		}
		if err := verifyScope(scope); err != nil {
			t.Error("L3 rollback scope", err)
			return
		}
		for _, prefix := range nativeWANAddresses(t, scope) {
			if prefix == lease.Event.Address {
				nativeIP(t, "address", "del", lease.Event.Address, "dev", scope.Interface)
			}
		}
		if len(nativeWANAddresses(t, scope)) != 0 {
			t.Error("L3 rollback left WAN state")
			return
		}
		removed = true
	}
	t.Cleanup(remove)
	nativeIP(t, "address", "add", lease.Event.Address, "dev", scope.Interface)
	addresses := nativeWANAddresses(t, scope)
	if len(addresses) != 1 || addresses[0] != lease.Event.Address {
		t.Fatal("L3 delta readback")
	}
	return remove
}

func nativeWANAddresses(t *testing.T, scope Scope) []string {
	t.Helper()
	iface, err := net.InterfaceByName(scope.Interface)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			t.Fatal("interface address format")
		}
		if prefix.Addr().Is4() {
			result = append(result, prefix.String())
		}
	}
	return result
}

func nativeIP(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/bin/ip", append([]string{"-4"}, args...)...).Run(); err != nil {
		t.Fatal("fixed fixture L3 operation", err)
	}
}

func stopNativeServer(t *testing.T) {
	t.Helper()
	// Only the private-PID-namespace harness supplies this child identity.
	pid, err := strconv.Atoi(os.Getenv("ANDEIVA_DHCP_SERVER_PID"))
	if err != nil || pid <= 1 {
		t.Fatal("server identity")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if fd < 0 || fd > 1<<31-1 {
		t.Fatal("pidfd range")
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal(err)
	}
	// Sending a signal alone is not proof that the server can no longer reply.
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 3000)
	if err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatal("server death not observed", err)
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
			c.mu.Lock()
			stage, reason, code := c.failure, c.lastReason, c.exitCode
			c.mu.Unlock()
			t.Fatalf("dhcpcd exited before acquisition: stage=%s last_reason=%s exit=%d", stage, reason, code)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.mu.Lock()
	stage, reason := c.failure, c.lastReason
	c.mu.Unlock()
	t.Fatalf("lease acquisition deadline: stage=%s last_reason=%s", stage, reason)
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
