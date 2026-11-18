//go:build linux

package previewruntime

import (
	"context"
	"math"
	"os"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const (
	routedDHCPWANClientV2 = 1
	routedDHCPLANServerV2 = 2
)

// The authenticated catalog reports the two reserved slots. It carries no
// selected configuration or permission to change either service.
type routedDHCPServiceCatalogV2 struct {
	Version int                         `json:"version"`
	Parent  routedDHCPServiceIdentityV2 `json:"parent"`
	Leaves  []routedDHCPServiceLeafV2   `json:"leaves"`
}

type routedDHCPServiceLeafV2 struct {
	Purpose     int                         `json:"purpose"`
	Incarnation string                      `json:"incarnation"`
	Identity    routedDHCPServiceIdentityV2 `json:"identity"`
}

type routedDHCPServiceIdentityV2 struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (c routedDHCPServiceCatalogV2) expectedPins() ([]RoutedDHCPServerCgroupPinV1, error) {
	if c.Version != 2 || c.Parent.Device == 0 || c.Parent.Inode == 0 || len(c.Leaves) != 2 {
		return nil, ErrIdentity
	}
	var result []RoutedDHCPServerCgroupPinV1
	for i, role := range []string{"wan", "lan"} {
		leaf := c.Leaves[i]
		name, err := routedDHCPServerCgroupNameV1(role, leaf.Incarnation)
		if err != nil || leaf.Purpose != i+1 || leaf.Identity.Device != c.Parent.Device ||
			leaf.Identity.Inode == 0 || leaf.Identity == c.Parent || i > 0 && leaf.Identity == c.Leaves[0].Identity {
			return nil, ErrIdentity
		}
		result = append(result, RoutedDHCPServerCgroupPinV1{Role: role, Name: name, Identity: RoutedDHCPServiceCgroupIdentityV1(leaf.Identity)})
	}
	return result, nil
}

func (s *RoutedDHCPServerServiceSetV1) catalogV2(ctx context.Context) (routedDHCPServiceCatalogV2, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return routedDHCPServiceCatalogV2{}, ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retiring || s.verifyUnderV1() != nil {
		return routedDHCPServiceCatalogV2{}, ErrIdentity
	}
	parent, err := routedDHCPServiceDirectoryV1(s.parent)
	if err != nil {
		return routedDHCPServiceCatalogV2{}, err
	}
	catalog := routedDHCPServiceCatalogV2{Version: 2, Parent: routedDHCPServiceIdentityV2(parent), Leaves: []routedDHCPServiceLeafV2{
		{Purpose: routedDHCPWANClientV2, Incarnation: strings.TrimPrefix(s.wan.name, "dhcp-"), Identity: routedDHCPServiceIdentityV2(s.wan.identity)},
		{Purpose: routedDHCPLANServerV2, Incarnation: strings.TrimPrefix(s.lan.name, "dhcp-server-"), Identity: routedDHCPServiceIdentityV2(s.lan.identity)},
	}}
	if _, err := catalog.expectedPins(); err != nil || ctx.Err() != nil {
		return routedDHCPServiceCatalogV2{}, ErrIdentity
	}
	return catalog, nil
}

func validateRoutedDHCPServiceCatalogV2(parent *os.File, catalog routedDHCPServiceCatalogV2) error {
	pins, err := catalog.expectedPins()
	if err != nil {
		return err
	}
	parentID, err := routedDHCPServiceDirectoryV1(parent)
	if err != nil || RoutedDHCPServiceCgroupIdentityV1(catalog.Parent) != parentID {
		return ErrIdentity
	}
	return validateRoutedDHCPServerCgroupTopologyV1(parent, parentID, pins)
}

func (c routedDHCPServiceCatalogV2) matchesWANV2(incarnation string, id RoutedDHCPServiceCgroupIdentityV1) bool {
	pins, err := c.expectedPins()
	name, nameErr := routedDHCPServerCgroupNameV1("wan", incarnation)
	return err == nil && nameErr == nil && pins[0].Name == name && pins[0].Identity == id
}

func validateRoutedDHCPWANServiceRoleV2(pin *os.File, incarnation string, id RoutedDHCPServiceCgroupIdentityV1, catalog routedDHCPServiceCatalogV2) error {
	actual, err := routedDHCPServiceDirectoryV1(pin)
	group, groupErr := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	name, nameErr := routedDHCPServerCgroupNameV1("wan", incarnation)
	if err != nil || groupErr != nil || nameErr != nil || actual != id || !catalog.matchesWANV2(incarnation, id) ||
		string(group) != "0::"+routedSupervisorCgroupV3+"/"+name+"\n" {
		return ErrIdentity
	}
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := validateRoutedDHCPServiceCatalogV2(parent, catalog); err != nil {
		return err
	}
	return routedDHCPServiceTreeV1(pin, "", RoutedDHCPServiceCgroupIdentityV1{})
}

func (c *routedDHCPJobClientV4) verifyWANServiceTreeV2(ctx context.Context, incarnation string, id RoutedDHCPServiceCgroupIdentityV1) error {
	catalog, err := c.serviceTree(ctx)
	if err != nil || !catalog.matchesWANV2(incarnation, id) {
		return ErrIdentity
	}
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		return err
	}
	defer parent.Close()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return validateRoutedDHCPServiceCatalogV2(parent, catalog)
}

func routedDHCPServiceTreeJobV5(q routedDHCPJobV4, m Metadata, last uint64) bool {
	return q.Version == 5 && q.Operation == "service_tree" && q.Run == m.RunID && q.Namespace == m.GatewayNamespace &&
		last != math.MaxUint64 && q.Sequence == last+1 && q.Work == (configpoc.RoutedWorkReferenceV1{})
}

func (c *routedDHCPJobClientV4) serviceTree(ctx context.Context) (routedDHCPServiceCatalogV2, error) {
	reply, _, err := c.callVersion(ctx, 5, "service_tree", configpoc.RoutedWorkReferenceV1{})
	if err != nil {
		return routedDHCPServiceCatalogV2{}, err
	}
	return *reply.ServiceTree, nil
}
