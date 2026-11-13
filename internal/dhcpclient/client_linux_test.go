//go:build linux

package dhcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRenewAndRebindSignalRetainedChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDHCPControlSignalProcess$")
	cmd.Env = append(os.Environ(), "ANDEIVA_DHCP_SIGNAL_TEST=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	s := bufio.NewScanner(out)
	if !s.Scan() || s.Text() != "ready" {
		t.Fatal("signal receiver not ready")
	}
	c := &Client{cmd: cmd}
	if err := c.Renew(); err != nil {
		t.Fatal(err)
	}
	if !s.Scan() || s.Text() != syscall.SIGUSR1.String() {
		t.Fatal("renew did not signal SIGUSR1")
	}
	if err := c.Rebind(); err != nil {
		t.Fatal(err)
	}
	if !s.Scan() || s.Text() != syscall.SIGHUP.String() {
		t.Fatal("rebind did not signal SIGHUP")
	}
	c.invalidate()
	if !errors.Is(c.Renew(), ErrUnavailable) || !errors.Is(c.Rebind(), ErrUnavailable) {
		t.Fatal("dead owner accepts controls")
	}
}

func TestDHCPControlSignalProcess(t *testing.T) {
	if os.Getenv("ANDEIVA_DHCP_SIGNAL_TEST") != "1" {
		return
	}
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGUSR1, syscall.SIGHUP, syscall.SIGALRM)
	defer signal.Stop(ch)
	fmt.Println("ready")
	for range 2 {
		fmt.Println(<-ch)
	}
}

func TestEventPipeRejectsAmbiguousAndOversizeRecords(t *testing.T) {
	e, _ := HookEvent(goodEnv(), 100)
	b, _ := json.Marshal(e)
	if _, err := decodeEvent(b); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"{}", string(b) + "{}", strings.Replace(string(b), `"pid":123`, `"pid":123,"pid":123`, 1), strings.Replace(string(b), `"pid":123`, `"pid":123,"PID":123`, 1), strings.Replace(string(b), `"pid":123`, `"pid":123,"shell":"id"`, 1), strings.Repeat(" ", MaxEventBytes)} {
		if _, err := decodeEvent([]byte(bad)); err == nil {
			t.Fatal("ambiguous record accepted")
		}
	}
}

func TestReconfigureRevokesWithoutKillingOwner(t *testing.T) {
	sec := int64(time.Second)
	c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec}
	bound, err := HookEvent(goodEnv(), 15*sec)
	if err != nil || c.accept(bound, 15*sec) != nil {
		t.Fatal("initial grant", err)
	}
	// dhcpcd if_reboot emits this BEFORE attempting a new DHCP exchange.
	e, err := HookEvent(replace(goodEnv(), "reason", "RECONFIGURE"), 16*sec)
	if err != nil {
		t.Fatal("documented rebind notification rejected", err)
	}
	b, _ := json.Marshal(e)
	e, err = decodeEvent(b)
	if err != nil || c.accept(e, 16*sec) != nil {
		t.Fatal("reconfigure channel rejected", err)
	}
	if _, err := c.currentAt(16 * sec); err == nil || c.failed {
		t.Fatal("reconfigure granted or killed owner")
	}
	bound.Reason = "REBOOT"
	bound.BootNS = 17 * sec
	if c.accept(bound, 17*sec) != nil {
		t.Fatal("fresh confirmed rebind rejected")
	}
	lease, err := c.currentAt(17 * sec)
	if err != nil || lease.Epoch != 2 || lease.DeadlineBootNS != 135*sec {
		t.Fatal("reconfigure extended validity", lease, err)
	}
}

func TestConservativeLeaseExpiryRenewalAndRevocation(t *testing.T) {
	sec := int64(time.Second)
	c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec}
	e, err := HookEvent(goodEnv(), 15*sec)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.accept(e, 15*sec); err != nil {
		t.Fatal(err)
	}
	l, err := c.currentAt(16 * sec)
	if err != nil || l.DeadlineBootNS != 130*sec || l.Epoch != 1 {
		t.Fatal(l, err)
	}
	l.Event.DNS[0] = "203.0.113.1"
	l, _ = c.currentAt(16 * sec)
	if l.Event.DNS[0] != "198.18.1.1" {
		t.Fatal("mutable lease escaped")
	}
	// Renewal uses the previous hook as a lower bound, never current arrival.
	e.Reason = "RENEW"
	e.BootNS = 75 * sec
	if err = c.accept(e, 75*sec); err != nil {
		t.Fatal(err)
	}
	l, err = c.currentAt(134 * sec)
	if err != nil || l.DeadlineBootNS != 135*sec || l.Epoch != 2 {
		t.Fatal(l, err)
	}
	if _, err = c.currentAt(135 * sec); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired lease returned", err)
	}
	e.Reason = "REBIND"
	e.BootNS = 135 * sec
	if err = c.accept(e, 135*sec); err != nil {
		t.Fatal(err)
	}
	for i, reason := range []string{"NAK", "EXPIRE", "TIMEOUT", "NOCARRIER", "STOP", "FAIL"} {
		c.lease = l
		revoke := Event{Version: 1, Interface: "wan0", Reason: reason, PID: 123, BootNS: int64(136+i) * sec}
		if err = c.accept(revoke, int64(136+i)*sec); err != nil {
			t.Fatal(err)
		}
		if _, err = c.currentAt(136 * sec); err == nil {
			t.Fatal("revoked lease returned", reason)
		}
	}
}

func TestLeaseRejectsReplayForeignOwnerDelayAndRestart(t *testing.T) {
	sec := int64(time.Second)
	e, _ := HookEvent(goodEnv(), 15*sec)
	for _, mutate := range []func(*Event){
		func(e *Event) { e.PID++ }, func(e *Event) { e.Interface = "lan0" },
		func(e *Event) { e.BootNS = 9 * sec }, func(e *Event) { e.BootNS = 16 * sec },
		func(e *Event) { e.BootNS = 12 * sec },
	} {
		c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec, lastEvent: 10 * sec}
		bad := e
		mutate(&bad)
		if c.accept(bad, 15*sec) == nil {
			t.Fatal("foreign/stale event accepted", bad)
		}
	}
	c := &Client{iface: "wan0", pid: 124, lastGrant: 20 * sec}
	if c.accept(e, 21*sec) == nil {
		t.Fatal("old owner accepted after restart")
	}
	if _, err := c.currentAt(21 * sec); err == nil {
		t.Fatal("restart resurrected evidence")
	}
	c = &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec}
	if err := c.accept(e, 15*sec); err != nil {
		t.Fatal(err)
	}
	if c.accept(e, 15*sec) == nil {
		t.Fatal("duplicate hook accepted")
	}
	c.invalidate()
	e.BootNS = 16 * sec
	if c.accept(e, 16*sec) == nil {
		t.Fatal("dead channel revived")
	}
}

func TestStartRejectsHostBeforeFilesystemEffects(t *testing.T) {
	h, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	m, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := StartIsolated(context.Background(), Scope{HostNetwork: h, HostMount: m, Interface: "wan0", Index: 1, HardwareAddress: "02:00:00:00:00:01"}); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}
