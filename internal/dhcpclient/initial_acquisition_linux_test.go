//go:build linux

package dhcpclient

import (
	"testing"
	"time"
)

func TestInitialAcquisitionSnapshotIrreversible(t *testing.T) {
	sec := int64(time.Second)
	for _, reason := range []string{"PREINIT", "CARRIER", "BOUND", "NOCARRIER", "EXPIRE", "NAK", "STOP", "STOPPED", "DEPARTED", "FAIL", "TIMEOUT", "RECONFIGURE"} {
		t.Run(reason, func(t *testing.T) {
			c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec, initialWaiting: true}
			e, err := HookEvent(replace(goodEnv(), "reason", reason), 15*sec)
			if err != nil || c.accept(e, 15*sec) != nil {
				t.Fatal("event", err)
			}
			l, state, err := c.acquisitionAt(16 * sec)
			switch reason {
			case "PREINIT", "CARRIER":
				if err != nil || state != AcquisitionInitialWaiting || l.Epoch != 0 {
					t.Fatal(state, err)
				}
			case "BOUND":
				if err != nil || state != AcquisitionGranted || l.Epoch != 1 {
					t.Fatal(state, err)
				}
				if _, state, err = c.acquisitionAt(200 * sec); err == nil || state != AcquisitionUnavailable {
					t.Fatal("expiry became initial wait", state, err)
				}
			default:
				if err == nil || state != AcquisitionUnavailable {
					t.Fatal("revocation became initial wait", state, err)
				}
			}
			if reason != "PREINIT" && reason != "CARRIER" {
				for i, initial := range []string{"PREINIT", "CARRIER"} {
					e, err = HookEvent(replace(goodEnv(), "reason", initial), int64(201+i)*sec)
					if err != nil || c.accept(e, int64(201+i)*sec) != nil {
						t.Fatal(err)
					}
				}
				if _, state, _ = c.acquisitionAt(203 * sec); state == AcquisitionInitialWaiting {
					t.Fatal("initial phase revived")
				}
			}
			c.failAt("event_channel_closed")
			if _, state, err = c.acquisitionAt(204 * sec); err == nil || state != AcquisitionUnavailable {
				t.Fatal("failure became initial wait")
			}
		})
	}
	var empty Client
	if _, state, err := empty.AcquisitionSnapshot(); err == nil || state != AcquisitionUnavailable {
		t.Fatal("zero client acquired waiting status")
	}
}

// Both possible linearizations of BOUND are coherent: the first read may be
// waiting, but a read released after the event commit must return that lease.
func TestInitialAcquisitionSnapshotAtomicBound(t *testing.T) {
	sec := int64(time.Second)
	c := &Client{iface: "wan0", pid: 123, lastGrant: 10 * sec, initialWaiting: true}
	if _, state, err := c.acquisitionAt(14 * sec); err != nil || state != AcquisitionInitialWaiting {
		t.Fatal(state, err)
	}
	bound, err := HookEvent(goodEnv(), 15*sec)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.accept(bound, 15*sec); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	started := make(chan struct{})
	done := make(chan AcquisitionState, 1)
	go func() {
		close(started)
		l, state, err := c.acquisitionAt(16 * sec)
		if err != nil || l.Epoch != 1 {
			state = AcquisitionUnavailable
		}
		done <- state
	}()
	<-started
	c.mu.Unlock()
	if state := <-done; state != AcquisitionGranted {
		t.Fatal("atomic BOUND snapshot lost lease", state)
	}
}
