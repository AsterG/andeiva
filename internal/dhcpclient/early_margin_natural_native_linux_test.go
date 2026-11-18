//go:build linux

package dhcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// No renewal signal or recovery probe is sent by this fixture. The engine's
// natural timer must produce each new grant while the policy mask is closed.
func TestNativeDHCPEarlyMarginNatural(t *testing.T) {
	length, err := strconv.Atoi(os.Getenv("ANDEIVA_DHCP_NATURAL_LEASE"))
	if os.Getenv("ANDEIVA_DHCP_NATIVE") != "1" || length != 70 && length != 71 {
		t.Skip("authorized natural renewal laboratory only")
	}
	if os.Geteuid() != 0 || os.Getuid() != 0 || os.Getenv("CI") != "" {
		t.Fatal("isolated root laboratory only")
	}
	hostNet, hostMount := os.NewFile(3, "host-net"), os.NewFile(4, "host-mount")
	defer hostNet.Close()
	defer hostMount.Close()
	iface, err := net.InterfaceByName("wan0")
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{HostNetwork: hostNet, HostMount: hostMount, Interface: iface.Name, Index: iface.Index, HardwareAddress: iface.HardwareAddr.String(), EarlyRenewalV4: true}
	if verifyScope(scope) != nil {
		t.Fatal("non-isolated fixture")
	}
	baseline := nativeBaseline(t)
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	defer cancel()
	c, err := StartIsolated(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	first := nativeMarginInternalGrant(t, ctx, c, 0)
	if first.Event.Seconds != uint32(length) {
		t.Fatal("unexpected natural lease duration")
	}
	// Install only the lab's private WAN address so the real client can receive
	// its UDP renewal. This internal snapshot grants no forwarding permission.
	remove := nativeApplyWANLease(t, scope, first)
	defer remove()
	c.closeEarlyMargin("early_short_lease")
	if o, err := c.ObserveAcquisition(); err != nil || o.State != AcquisitionMarginClosed || !reflect.DeepEqual(o.Lease, Lease{}) {
		t.Fatal("B2 did not mask authority", o.State, err)
	}
	wantEpochs := 1
	if length == 70 {
		wantEpochs = 2
	}
	last := first
	type sample struct {
		Epoch             uint64           `json:"epoch"`
		HookDeltaNS       int64            `json:"hook_delta_ns"`
		EffectiveExcessNS int64            `json:"effective_excess_ns"`
		RemainingNS       int64            `json:"remaining_ns"`
		State             AcquisitionState `json:"state"`
	}
	var samples []sample
	for range wantEpochs {
		next := nativeMarginInternalGrant(t, ctx, c, last.Epoch)
		now, e := bootNow()
		if e != nil {
			t.Fatal(e)
		}
		o, e := c.ObserveAcquisition()
		if e != nil {
			t.Fatal(e)
		}
		delta := next.Event.BootNS - last.Event.BootNS
		samples = append(samples, sample{next.Epoch, delta, delta - int64(time.Duration(length/2)*time.Second), next.DeadlineBootNS - now, o.State})
		if length == 70 && o.State != AcquisitionMarginClosed {
			t.Fatal("below-boundary grant reopened despite insufficient measured margin")
		}
		if length == 71 && o.State != AcquisitionGranted {
			t.Fatalf("above-boundary natural grant has insufficient measured margin: %dns", next.DeadlineBootNS-now)
		}
		last = next
	}
	c.Stop()
	remove()
	if got := nativeBaseline(t); !bytes.Equal(got, baseline) {
		t.Fatal("native host/private baseline changed")
	}
	raw, err := os.ReadFile("/run/andeiva-dhcp/native-diagnostics/events.jsonl")
	if err != nil || len(raw) > clientDiagnosticNativeLimitV4 {
		t.Fatal("native diagnostic unavailable", err)
	}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	signals := 0
	marginEvents := 0
	for scan.Scan() {
		var e struct {
			Stage string `json:"stage"`
		}
		if json.Unmarshal(scan.Bytes(), &e) != nil {
			t.Fatal("invalid native diagnostic")
		}
		if e.Stage == "early_signal" {
			signals++
		}
		if e.Stage == "early_margin_closed" {
			marginEvents++
		}
		if e.Stage == "truncated" {
			t.Fatal("truncated diagnostic")
		}
	}
	if scan.Err() != nil || signals != 0 || marginEvents != 1 {
		t.Fatalf("B2 sent a probe or repeated notice: signals=%d margin=%d", signals, marginEvents)
	}
	report, err := json.Marshal(struct {
		LeaseSeconds        int      `json:"lease_seconds"`
		T1AssumptionSeconds int      `json:"default_t1_seconds"`
		Samples             []sample `json:"samples"`
		Signals             int      `json:"signals"`
		MarginTransitions   int      `json:"margin_transitions"`
	}{length, length / 2, samples, signals, marginEvents})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ANDEIVA_DHCP_B2_NATURAL %s", report)
}

const clientDiagnosticNativeLimitV4 = 64 << 10

func nativeMarginInternalGrant(t *testing.T, ctx context.Context, c *Client, after uint64) Lease {
	t.Helper()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		c.mu.Lock()
		l, failed := c.lease, c.failed
		c.mu.Unlock()
		if failed {
			t.Fatal("natural acquisition owner failed")
		}
		if l.Epoch > after {
			return l
		}
		select {
		case <-ctx.Done():
			t.Fatal("natural grant timed out", ctx.Err())
		case <-tick.C:
		}
	}
}
