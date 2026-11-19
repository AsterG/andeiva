//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRoutedDHCPServiceCatalogV2PrivateChannel(t *testing.T) {
	const device = 1
	catalog := routedDHCPServiceCatalogV2{
		Version: 2,
		Parent:  routedDHCPServiceIdentityV2{Device: device, Inode: 1},
		Leaves: []routedDHCPServiceLeafV2{
			{Purpose: routedDHCPWANClientV2, Incarnation: strings.Repeat("a", 32), Identity: routedDHCPServiceIdentityV2{Device: device, Inode: 2}},
			{Purpose: routedDHCPLANServerV2, Incarnation: strings.Repeat("b", 32), Identity: routedDHCPServiceIdentityV2{Device: device, Inode: 3}},
		},
	}
	boot := routedDHCPOwnerBootstrapV3{Version: 4, ServiceCgroupVersion: 2, ServiceCatalog: &catalog}
	raw, err := json.Marshal(boot)
	var decoded routedDHCPOwnerBootstrapV3
	if err != nil || routedDHCPOwnerDecodeV3(raw, &decoded) != nil || !reflect.DeepEqual(decoded.ServiceCatalog, &catalog) {
		t.Fatal("strict owner bootstrap failed to round-trip the service catalog")
	}

	for _, test := range []struct {
		name      string
		broker    bool
		client    bool
		malformed bool
	}{
		{name: "authenticated", broker: true, client: true},
		{name: "old client", broker: true},
		{name: "old broker", client: true},
		{name: "reused inode", client: true, broker: true, malformed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			m, _, _ := jobSourceFixtureV4(t, newJobOwnerFixtureV4(t).binding)
			root, helper, peer := jobChannelFixtureV4(t)
			b := &routedDHCPJobBrokerV4{}
			if test.broker {
				b.serviceTree = func(context.Context) (routedDHCPServiceCatalogV2, error) {
					if test.malformed {
						bad := catalog
						bad.Leaves = append([]routedDHCPServiceLeafV2{}, catalog.Leaves...)
						bad.Leaves[1].Identity = bad.Leaves[0].Identity
						return bad, nil
					}
					return catalog, nil
				}
			}
			done := make(chan error, 1)
			go func() { done <- b.serve(ctx, root, m, peer) }()
			client := &routedDHCPJobClientV4{conn: helper, metadata: m, peer: peer, servicesEnabled: test.client}
			got, err := client.serviceTree(ctx)
			if want := test.broker && test.client && !test.malformed; (err == nil) != want || want && !reflect.DeepEqual(got, catalog) {
				t.Fatalf("catalog = %+v, error = %v", got, err)
			}
			_ = client.Close()
			if test.client && (!test.broker || test.malformed) {
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("incompatible or malformed profile was accepted")
					}
				case <-ctx.Done():
					t.Fatal("invalid catalog did not drain")
				}
			}
		})
	}
}
