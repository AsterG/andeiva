//go:build linux

package networkinventory

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

func TestLinuxClassificationDoesNotFollowForeignTargets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		links    map[string]string
		want     Kind
		maxReads int
	}{
		{"virtual", map[string]string{"/sys/class/net/test0": "../../devices/virtual/net/test0"}, Virtual, 1},
		{"device-backed", map[string]string{"/sys/class/net/test0": "../../devices/pci0000:00/0000:00:01.0/net/test0", "/sys/devices/pci0000:00/0000:00:01.0/net/test0/device": "../../"}, DeviceBacked, 2},
		{"missing", nil, Unknown, 1},
		{"foreign-class", map[string]string{"/sys/class/net/test0": "/etc/private"}, Unknown, 1},
		{"prefix-confusion", map[string]string{"/sys/class/net/test0": "/sys/devices-other/test0"}, Unknown, 1},
		{"foreign-device", map[string]string{"/sys/class/net/test0": "../../devices/pci/net/test0", "/sys/devices/pci/net/test0/device": "/etc/private"}, Unknown, 2},
		{"oversized", map[string]string{"/sys/class/net/test0": strings.Repeat("x", 4097)}, Unknown, 1},
		{"nondevice", map[string]string{"/sys/class/net/test0": "../../devices/platform/net/test0"}, Unknown, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			got := classifyLinux("test0", func(path string) (string, error) {
				reads++
				if reads > tc.maxReads {
					t.Fatal("unexpected filesystem lookup")
				}
				value, exists := tc.links[path]
				if !exists {
					return "", fs.ErrNotExist
				}
				return value, nil
			})
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	if got := classifyLinux("../private", func(string) (string, error) { t.Fatal("unsafe name reached filesystem"); return "", nil }); got != Unknown {
		t.Fatalf("unsafe name accepted: %s", got)
	}
}

func TestLinuxReadOnlyRuntimeObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var snapshot Snapshot
	var err error
	for range 3 {
		snapshot, err = Discover(ctx)
		if !errors.Is(err, ErrChanged) {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	loopback := false
	for _, iface := range snapshot.Interfaces {
		loopback = loopback || iface.Kind == Loopback
		if iface.Index <= 0 || !validName(iface.Name) {
			t.Fatal("invalid observed identity")
		}
		for _, address := range iface.Addresses {
			if !address.IP.IsValid() {
				t.Fatal("invalid observed address")
			}
		}
	}
	if !loopback {
		t.Fatal("Linux observation did not include its loopback interface")
	}
}

func BenchmarkDiscoverLinux(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Discover(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
