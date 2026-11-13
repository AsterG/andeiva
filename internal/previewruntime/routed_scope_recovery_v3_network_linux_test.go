//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func scopeRecoveryLinkFixtureV3() []routedLinkObservationV3 {
	links := []routedLinkObservationV3{{Index: 1, Name: "lo", Flags: []string{"LOOPBACK"}}}
	for i, name := range []string{"lan0", "wan0"} {
		link := routedLinkObservationV3{Index: i + 2, Name: name, MAC: []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}[i], MTU: 1500, Parent: i + 10, Flags: []string{"UP"}}
		link.Info.Kind = "macvlan"
		link.Info.Data.Mode = "private"
		links = append(links, link)
	}
	return links
}
func TestRoutedScopeRecoveryV3CloseNetworkFailureBoundaries(t *testing.T) {
	for _, failure := range []string{"", "close", "forward_read", "links_read", "foreign", "remove", "retained_link", "changed_other", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			links := scopeRecoveryLinkFixtureV3()
			calls := []scopeRecoveryNetworkOpV3{}
			removes := 0
			run := func(_ context.Context, op scopeRecoveryNetworkOpV3) ([]byte, error) {
				calls = append(calls, op)
				switch op {
				case scopeRecoveryForwardCloseV3:
					if failure == "close" {
						return nil, ErrUnavailable
					}
				case scopeRecoveryForwardReadV3:
					if failure == "forward_read" {
						return []byte("1\n0\n0\n0\n"), nil
					}
					return []byte("0\n0\n0\n0\n"), nil
				case scopeRecoveryLinksReadV3:
					if failure == "links_read" {
						return nil, ErrUnavailable
					}
					if failure == "foreign" {
						links[1].Info.Kind = "physical"
					}
					raw, err := json.Marshal(links)
					return raw, err
				case scopeRecoveryWANRemoveV3, scopeRecoveryLANRemoveV3:
					removes++
					if failure == "remove" {
						return nil, ErrUnavailable
					}
					if failure == "cancel" {
						cancel()
						return nil, ctx.Err()
					}
					if failure == "retained_link" {
						return nil, nil
					}
					name := "wan0"
					if op == scopeRecoveryLANRemoveV3 {
						name = "lan0"
					}
					for i, link := range links {
						if link.Name == name {
							links = append(links[:i], links[i+1:]...)
							break
						}
					}
					if failure == "changed_other" {
						links[1].Index++
					}
				}
				return nil, nil
			}
			err := closeScopeRecoveryNetworkV3(ctx, run)
			if (err == nil) != (failure == "") {
				t.Fatal(failure, err)
			}
			if len(calls) == 0 || calls[0] != scopeRecoveryForwardCloseV3 {
				t.Fatal("effects preceded forwarding closure")
			}
			if failure == "" {
				want := []scopeRecoveryNetworkOpV3{scopeRecoveryForwardCloseV3, scopeRecoveryForwardReadV3, scopeRecoveryLinksReadV3, scopeRecoveryWANRemoveV3, scopeRecoveryLinksReadV3, scopeRecoveryLANRemoveV3, scopeRecoveryLinksReadV3, scopeRecoveryForwardReadV3}
				if !reflect.DeepEqual(calls, want) || len(links) != 1 {
					t.Fatal("incomplete teardown", calls)
				}
			}
			if (failure == "close" || failure == "forward_read" || failure == "links_read" || failure == "foreign") && removes != 0 {
				t.Fatal("uncertain proof allowed link removal")
			}
			if (failure == "retained_link" || failure == "changed_other") && removes != 1 {
				t.Fatal("continued after inconsistent readback")
			}
		})
	}
	if _, err := scopeRecoveryNetworkArgumentsV3(255); err == nil {
		t.Fatal("unknown operation accepted")
	}
}
func TestRoutedScopeRecoveryV3CleanupSocketRequiresExactNode(t *testing.T) {
	directory := t.TempDir()
	area, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "routed.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(filepath.Join(directory, "routed.sock"), 0660); err != nil {
		t.Fatal(err)
	}
	ids := Identities{HelperUID: uint32(os.Getuid()), IPCGID: uint32(os.Getgid())}
	first, err := scopeCleanupSocketV3(area, "routed.sock", ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = scopeCleanupSocketV3(area, "../routed.sock", ids); !errors.Is(err, ErrIdentity) {
		t.Fatal("path escaped", err)
	}
	if err = area.WriteFile("compat.sock", []byte("not a socket"), 0660); err != nil {
		t.Fatal(err)
	}
	if _, err = scopeCleanupSocketV3(area, "compat.sock", ids); err == nil {
		t.Fatal("regular file accepted as stale socket")
	}
	if err = os.Chmod(filepath.Join(directory, "routed.sock"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = scopeCleanupSocketV3(area, "routed.sock", ids); err == nil {
		t.Fatal("wide permissions accepted")
	}
	if _, err = area.Lstat("routed.sock"); err != nil {
		t.Fatal("validation mutated socket", err)
	}
	if first == nil {
		t.Fatal("no captured identity")
	}
}
