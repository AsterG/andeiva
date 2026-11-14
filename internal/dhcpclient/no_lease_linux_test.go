//go:build linux

package dhcpclient

import (
	"reflect"
	"testing"
	"time"
)

func TestAcquisitionNoLeaseAtomicRevocationAndRecovery(t *testing.T) {
	sec := int64(time.Second)
	c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec, initialWaiting: true}
	for _, step := range []struct {
		reason string
		at     int64
		state  AcquisitionState
		epoch  uint64
	}{{"BOUND", 15, AcquisitionGranted, 1}, {"RENEW", 75, AcquisitionGranted, 2}, {"EXPIRE", 76, AcquisitionNoLease, 2}, {"BOUND", 81, AcquisitionGranted, 3}} {
		e, err := HookEvent(replace(goodEnv(), "reason", step.reason), step.at*sec)
		if err != nil || c.accept(e, step.at*sec) != nil {
			t.Fatal(step.reason, err)
		}
		o, err := c.observationAt(step.at * sec)
		if err != nil || o.State != step.state || o.ObservedEpoch != step.epoch {
			t.Fatal("atomic phase/epoch", step.reason, o, err)
		}
		if step.state == AcquisitionNoLease && !reflect.DeepEqual(o.Lease, Lease{}) {
			t.Fatal("revocation retained a grant")
		}
		if step.reason == "BOUND" && step.epoch == 3 && o.Lease.DeadlineBootNS != 195*sec {
			t.Fatal("reacquisition extended original conservative clock")
		}
	}
	if o, err := c.observationAt(196 * sec); err != nil || o.State != AcquisitionNoLease || o.ObservedEpoch != 3 {
		t.Fatal("expiry without hook", o, err)
	}
	c.failAt("event_channel_closed")
	if o, err := c.observationAt(197 * sec); err == nil || o.State != AcquisitionUnavailable {
		t.Fatal("failed source became no-lease")
	}
}

func TestAcquisitionNoLeaseNeverCoversTerminalOrUnconfirmedSource(t *testing.T) {
	sec := int64(time.Second)
	for _, reason := range []string{"STOP", "STOPPED", "FAIL", "DEPARTED", "TIMEOUT"} {
		c := &Client{iface: "wan0", pid: 123, epoch: 1, lastGrant: 10 * sec}
		e, err := HookEvent(replace(goodEnv(), "reason", reason), 15*sec)
		if err != nil || c.accept(e, 15*sec) != nil {
			t.Fatal(err)
		}
		if o, err := c.observationAt(16 * sec); err == nil || o.State != AcquisitionUnavailable {
			t.Fatal("terminal event became lease-less health", reason)
		}
	}
	c := &Client{iface: "wan0", pid: 123, lastReason: "EXPIRE"}
	if o, err := c.observationAt(sec); err == nil || o.State != AcquisitionUnavailable {
		t.Fatal("unconfirmed epoch became no-lease")
	}
}
