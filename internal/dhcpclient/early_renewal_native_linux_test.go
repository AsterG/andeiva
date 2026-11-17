//go:build linux

package dhcpclient

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Component resource comparison only: this is not an integrated forwarding or
// TCP/UDP survival test. Both modes run the same observation load in fresh labs.
func TestNativeDHCPEarlyRenewalResources(t *testing.T) {
	mode := os.Getenv("ANDEIVA_DHCP_EARLY_PROFILE")
	if os.Getenv("ANDEIVA_DHCP_NATIVE") != "1" || mode != "off" && mode != "on" {
		t.Skip("requires isolated Debian early-renewal laboratory")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("CI") != "" {
		t.Fatal("authorized root laboratory only")
	}
	hostNet, hostMount := os.NewFile(3, "host-net"), os.NewFile(4, "host-mount")
	defer hostNet.Close()
	defer hostMount.Close()
	iface, err := net.InterfaceByName("wan0")
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{HostNetwork: hostNet, HostMount: hostMount, Interface: iface.Name, Index: iface.Index, HardwareAddress: iface.HardwareAddr.String(), EarlyRenewalV4: mode == "on"}
	if verifyScope(scope) != nil {
		t.Fatal("unisolated resource test")
	}
	baseline := nativeBaseline(t)
	ctx, cancel := context.WithTimeout(context.Background(), 185*time.Second)
	defer cancel()
	c, err := StartIsolated(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	first := awaitLease(t, c, 0, 35*time.Second)
	if first.Event.Seconds != 120 {
		t.Fatal("comparison requires same 120s lease", first.Event.Seconds)
	}
	remove := nativeApplyWANLease(t, scope, first)
	defer remove()
	var before, after unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &before) != nil {
		t.Fatal("owner CPU unavailable")
	}
	started, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	minG, maxG, maxRSS := int(^uint(0)>>1), 0, int64(0)
	last, renewals := first, 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		now, err := bootNow()
		if err != nil {
			t.Fatal(err)
		}
		if now-started >= int64(145*time.Second) {
			break
		}
		lease, err := c.Current()
		if err != nil {
			t.Fatal("resource window lost acquisition evidence", err)
		}
		if lease.Epoch > last.Epoch {
			if lease.Epoch != last.Epoch+1 || lease.Event.Reason != "RENEW" {
				t.Fatal("unexpected grant progression", lease.Epoch, lease.Event.Reason)
			}
			renewals++
			last = lease
		}
		g := runtime.NumGoroutine()
		if g < minG {
			minG = g
		}
		if g > maxG {
			maxG = g
		}
		raw, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(raw))
		if len(fields) != 7 {
			t.Fatal("invalid owner RSS")
		}
		pages, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || pages <= 0 {
			t.Fatal("invalid owner RSS", err)
		}
		rss := pages * int64(os.Getpagesize())
		if rss > maxRSS {
			maxRSS = rss
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	ended, err := bootNow()
	if err != nil || unix.Getrusage(unix.RUSAGE_SELF, &after) != nil {
		t.Fatal("owner resource observation failed", err)
	}
	if mode == "on" && renewals < 3 {
		t.Fatal("fewer than three actual early renewals", renewals)
	}
	if (c.early != nil) != (mode == "on") {
		t.Fatal("disabled mode created scheduler")
	}
	c.Stop()
	remove()
	if string(baseline) != string(nativeBaseline(t)) {
		t.Fatal("native baseline changed after cleanup")
	}
	cpu := after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano()
	report, err := json.Marshal(struct {
		Profile          string `json:"profile"`
		WindowNS         int64  `json:"window_ns"`
		OwnerCPUNS       int64  `json:"owner_cpu_ns"`
		OwnerRSSMaxBytes int64  `json:"owner_rss_max_bytes"`
		GoroutinesMin    int    `json:"goroutines_min"`
		GoroutinesMax    int    `json:"goroutines_max"`
		Renewals         int    `json:"renewals"`
	}{mode, ended - started, cpu, maxRSS, minG, maxG, renewals})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ANDEIVA_DHCP_B1_COMPONENT_RESOURCES %s", report)
}
