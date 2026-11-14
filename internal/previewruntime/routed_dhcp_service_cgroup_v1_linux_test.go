//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

func TestRoutedDHCPServiceBootstrapV1(t *testing.T) {
	good := routedDHCPOwnerBootstrapV3{Version: 4, ServiceCgroupVersion: 1, ServiceCgroupDevice: 2, ServiceCgroupInode: 3}
	for _, key := range []string{"", "service_cgroup_version", "service_cgroup_device", "service_cgroup_inode"} {
		t.Run("missing_"+key, func(t *testing.T) {
			raw, err := json.Marshal(good)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if key != "" {
				delete(fields, key)
			}
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var b routedDHCPOwnerBootstrapV3
			if err = routedDHCPOwnerDecodeV3(raw, &b); err != nil {
				t.Fatal(err)
			}
			valid := routedDHCPServiceBootstrapValidV1(b.ServiceCgroupVersion, RoutedDHCPServiceCgroupIdentityV1{b.ServiceCgroupDevice, b.ServiceCgroupInode})
			if valid != (key == "") {
				t.Fatalf("accepted=%v", valid)
			}
		})
	}
	for _, version := range []int{-1, 0, 2, 3, 4} {
		if routedDHCPServiceBootstrapValidV1(version, RoutedDHCPServiceCgroupIdentityV1{2, 3}) {
			t.Fatal("unknown service version accepted")
		}
	}
	var b routedDHCPOwnerBootstrapV3
	if routedDHCPOwnerDecodeV3([]byte(`{"version":4,"service_cgroup_version":1,"unexpected_service_authority":true}`), &b) == nil {
		t.Fatal("unknown authority accepted")
	}
	for _, nonce := range []string{"", "../escape", strings.Repeat("a", 31), strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		if _, e := routedDHCPServiceNameV1(nonce); e == nil {
			t.Fatal("invalid incarnation accepted")
		}
	}
	if name, e := routedDHCPServiceNameV1(strings.Repeat("a", 32)); e != nil || name != "dhcp-"+strings.Repeat("a", 32) {
		t.Fatal("canonical name rejected")
	}
}

func TestRoutedDHCPServiceRejectsNonCgroupDescriptorsV1(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "regular")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	d, e := os.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	fd, e := unix.Open("/proc/self", unix.O_PATH|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	p := os.NewFile(uintptr(fd), "path-only")
	defer p.Close()
	for _, file := range []*os.File{nil, f, d, r, w, p} {
		if _, e = routedDHCPServiceDirectoryV1(file); e == nil {
			t.Fatal("non-cgroup descriptor accepted")
		}
		if e = validateRoutedDHCPServiceRoleV1(file, strings.Repeat("a", 32), 1, RoutedDHCPServiceCgroupIdentityV1{1, 2}); e == nil {
			t.Fatal("unverified role accepted")
		}
	}
	if _, _, e := (*RoutedDHCPOwnerV3)(nil).RetainedServicePin(); e == nil {
		t.Fatal("nil owner accepted")
	}
	if _, _, e := (&RoutedDHCPOwnerV3{closed: true}).RetainedServicePin(); e == nil {
		t.Fatal("closed owner accepted")
	}
}

func TestRoutedDHCPServiceEventsV1(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		populated bool
		valid     bool
	}{
		{"populated 0\nfrozen 0\n", false, true},
		{"frozen 0\npopulated 1\n", true, true},
		{"", false, false}, {"populated 0\n", false, false},
		{"populated 0\nfrozen 1\n", false, false},
		{"populated 2\nfrozen 0\n", false, false},
		{"populated 0\npopulated 0\nfrozen 0\n", false, false},
		{"populated 0\nfrozen 0\nextra 0\n", false, false},
		{strings.Repeat("x", 257), false, false},
	} {
		got, e := routedDHCPServicePopulatedV1([]byte(tc.raw))
		if (e == nil) != tc.valid || tc.valid && got != tc.populated {
			t.Fatalf("events %q: %v %v", tc.raw, got, e)
		}
	}
}

// These exercise the drain algorithm with I/O doubles; native cgroup identity
// and descriptor lifetime are tested separately by the explicit root fixture.
func TestRoutedDHCPServiceDrainOrderingV1(t *testing.T) {
	var calls []string
	step := func(s string) func() error { return func() error { calls = append(calls, s); return nil } }
	err := drainRoutedDHCPServiceV1(context.Background(), step("verify"), step("kill"), func() (bool, error) { calls = append(calls, "empty"); return false, nil }, step("remove"))
	if err != nil || !reflect.DeepEqual(calls, []string{"verify", "kill", "verify", "empty", "verify", "remove"}) {
		t.Fatalf("%v %v", calls, err)
	}
}

func TestRoutedDHCPServiceDrainRejectsUncertaintyV1(t *testing.T) {
	for _, at := range []string{"before", "verify1", "verify2", "verify3", "kill", "events", "cancel_events", "cancel_verify", "remove"} {
		t.Run(at, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if at == "before" {
				cancel()
			}
			checks, kills, reads, removes := 0, 0, 0, 0
			failure := errors.New("injected I/O failure")
			err := drainRoutedDHCPServiceV1(ctx, func() error {
				checks++
				if at == "cancel_verify" {
					cancel()
				}
				if at == "verify1" && checks == 1 || at == "verify2" && checks == 2 || at == "verify3" && checks == 3 {
					return failure
				}
				return nil
			}, func() error {
				kills++
				if at == "kill" {
					return failure
				}
				return nil
			}, func() (bool, error) {
				reads++
				if at == "events" {
					return false, failure
				}
				if at == "cancel_events" {
					cancel()
				}
				return false, nil
			}, func() error { removes++; return failure })
			if err == nil {
				t.Fatal("uncertainty accepted")
			}
			if at != "remove" && removes != 0 {
				t.Fatal("removed after uncertainty")
			}
			if (at == "before" || at == "verify1" || at == "cancel_verify") && (kills != 0 || reads != 0) {
				t.Fatal("effects before verified live context")
			}
			if at == "remove" && removes != 1 {
				t.Fatal("missing removal failure")
			}
		})
	}
}

func TestRoutedDHCPServiceDrainDeadlineAndDelayedExitV1(t *testing.T) {
	for _, exit := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			reads, removes := 0, 0
			err := drainRoutedDHCPServiceV1(ctx, func() error { return nil }, func() error { return nil }, func() (bool, error) { reads++; return !(exit && reads == 2), nil }, func() error { removes++; return nil })
			if exit && (err != nil || removes != 1 || reads != 2) {
				t.Fatalf("delayed exit: %d %d %v", reads, removes, err)
			}
			if !exit && (!errors.Is(err, context.DeadlineExceeded) || removes != 0) {
				t.Fatalf("live processes removed: %v", err)
			}
		})
	}
}
