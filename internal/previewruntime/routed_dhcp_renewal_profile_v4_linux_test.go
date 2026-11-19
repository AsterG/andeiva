//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func TestRoutedDHCPRenewalV4BootstrapRequiresJobsAndIntegrity(t *testing.T) {
	for _, role := range []string{RoutedHelperRoleV3, RoutedAPIRoleV3} {
		for _, renewal := range []bool{false, true} {
			for _, jobs := range []bool{false, true} {
				for _, integrity := range []bool{false, true} {
					b := routedLaunchBootstrapV3{DHCPRenewalV4: renewal, DHCPJobs: jobs, Integrity: integrity}
					want := (!renewal || jobs) && (!jobs || integrity)
					if validRoutedScopeBootstrapV4(b, role) != want {
						t.Fatal("invalid profile dependency accepted", role, renewal, jobs, integrity)
					}
					if !want {
						continue
					}
					f := routedLaunchFilesV3{}
					if c := f.context(b); c.DHCPRenewalV4 != renewal || c.DHCPJobsEnabled != jobs {
						t.Fatal("child lost trusted profile")
					}
					raw, err := json.Marshal(b)
					if err != nil {
						t.Fatal(err)
					}
					var members map[string]json.RawMessage
					if json.Unmarshal(raw, &members) != nil {
						t.Fatal("invalid bootstrap")
					}
					_, present := members["dhcp_renewal_v4"]
					if present != renewal {
						t.Fatal("default emitted new optional member")
					}
				}
			}
		}
	}
	if err := validateRoutedLaunchV3(RoutedLaunchResourcesV3{DHCPRenewalV4: true}); err == nil {
		t.Fatal("root enabled renewal without jobs")
	}
}

func TestRoutedDHCPRenewalV4InheritedNegotiationKeepsPeerAndProfile(t *testing.T) {
	for _, mode := range []string{"v4", "legacy", "old-helper", "old-client", "uid", "gid", "pid"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := dhcpRuntimeFixtureV3(t)
			if mode != "legacy" && mode != "old-helper" {
				if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
					t.Fatal(err)
				}
			}
			s, err := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
			if err != nil {
				t.Fatal(err)
			}
			s.integrity = &routedIntegrityGateV3{}
			s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
				return networkinventory.Snapshot{}, ErrUnavailable
			}
			s.dhcp = r
			a, b := routedUnixPairV3(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.ServeRoutedV3(ctx, b, r.identity.RunID) }()
			uid, gid, pid := uint32(os.Geteuid()), uint32(os.Getegid()), int32(os.Getpid())
			switch mode {
			case "uid":
				uid++
			case "gid":
				gid++
			case "pid":
				pid++
			}
			var client *firewallipc.RoutedClientV3
			if mode == "legacy" || mode == "old-client" {
				client, err = ConnectInheritedRoutedDHCPV3(ctx, a, uid, gid, pid, r.identity.RunID, r.identity.Namespace)
			} else {
				client, err = ConnectInheritedRoutedDHCPRenewalV4(ctx, a, uid, gid, pid, r.identity.RunID, r.identity.Namespace, false, false)
			}
			want := mode == "v4" || mode == "legacy"
			if (err == nil) != want {
				t.Fatal("peer/profile mismatch admitted", mode, err)
			}
			if client != nil {
				if client.DHCPRenewalEnabledV4() != (mode == "v4") {
					t.Fatal("silent profile fallback")
				}
				_ = client.Close()
			}
			_ = a.Close()
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("negotiation retained child channel")
			}
		})
	}
}
