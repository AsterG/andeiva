//go:build linux

package previewruntime

import (
	"context"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routednft"
)

const routedDHCPLANListenerOwnerV1 = "andeiva-dhcp-lan"

type routedLANServiceObservationV1 struct {
	client   *routedDHCPJobClientV4
	work     configpoc.RoutedWorkReferenceV1
	start    routedDHCPServerJobProofV1
	cgroup   string
	bindings []routedDHCPServerSocketBindingV1
	declared []localpolicy.Listener
	config   *dhcpserver.Config
	network  string
	engine   routedKeaSocketProofV1
	stopped  bool
}

func newRoutedLANServiceObservationV1(ctx context.Context, client *routedDHCPJobClientV4, source RoutedSelectedPreflightResultV4, plan routedDHCPServerBindingPlanV1, start *routedDHCPServerJobProofV1) (*routedLANServiceObservationV1, error) {
	policy := source.Bundle.Firewall.Config.Routed
	if client == nil || policy == nil || policy.DHCPServer == nil || !policy.DHCPServer.Enabled ||
		!start.validV1("server_start") || len(start.Links) != len(plan) {
		return nil, ErrIdentity
	}
	catalog, err := client.serviceTree(ctx)
	if err != nil {
		return nil, err
	}
	pins, err := catalog.expectedPins()
	if err != nil || pins[1].Identity != start.Cgroup {
		return nil, ErrIdentity
	}
	lan := &routedLANServiceObservationV1{client: client, work: source.Work, start: *start,
		config: policy.DHCPServer, network: policy.Network.Hash, cgroup: "0::" + routedSupervisorCgroupV3 + "/" + pins[1].Name + "\n"}
	for i, scope := range plan {
		link := start.Links[i]
		if link.Name != scope.kea.Name || link.Address != scope.kea.Interface.Address || link.MAC != scope.subnet.HardwareMAC {
			return nil, ErrIdentity
		}
		lan.bindings = append(lan.bindings, routedDHCPServerSocketBindingV1{index: link.Index, address: link.Address.Addr()})
		lan.declared = append(lan.declared, localpolicy.Listener{
			Owner: routedDHCPLANListenerOwnerV1, Service: scope.subnet.ScopeID, Interface: link.Name,
			LocalAddress: link.Address.Addr().String(), Protocol: localpolicy.UDP, Port: 67,
		})
	}
	return lan, nil
}

// Called under verified deny before the grouped engine mutates owned links.
func (l *routedEmptyListenersV3) PrepareRoutedTransition(ctx context.Context, target *routednft.Policy, pending bool) error {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lan != nil && !l.lan.matches(target) {
		if err := l.releaseLANUnderV1(ctx); err != nil {
			return err
		}
	}
	l.pendingLAN = nil
	if l.lan == nil && enabledRoutedLANV1(target) {
		if !pending {
			return ErrUnavailable
		}
		l.pendingLAN = target
	}
	return nil
}

func (s *routedLANServiceObservationV1) matches(policy *routednft.Policy) bool {
	return !s.stopped && enabledRoutedLANV1(policy) && policy.Network.Hash == s.network && reflect.DeepEqual(policy.DHCPServer, s.config)
}

func enabledRoutedLANV1(policy *routednft.Policy) bool {
	return policy != nil && policy.DHCPServer != nil && policy.DHCPServer.Enabled
}

func (s *routedLANServiceObservationV1) proof(ctx context.Context, op string) (*routedKeaSocketProofV1, error) {
	if s.stopped {
		return nil, ErrUnavailable
	}
	p, err := s.client.callServerV1(ctx, op, s.work)
	if err != nil || p == nil || p.Engine == nil || p.RolePID != s.start.RolePID || p.UID != s.start.UID ||
		p.Cgroup != s.start.Cgroup || !slices.Equal(p.Links, s.start.Links) {
		return nil, ErrUnavailable
	}
	if s.engine.PID != 0 && (p.Engine.PID != s.engine.PID || p.Engine.Start != s.engine.Start) {
		return nil, ErrIdentity
	}
	start, ppid, err := routedDHCPOwnerProcessV3(p.Engine.PID)
	if err != nil || start != p.Engine.Start || ppid != p.RolePID {
		return nil, ErrIdentity
	}
	for _, pid := range []int{p.RolePID, p.Engine.PID} {
		cgroup, err := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(pid)+"/cgroup", 4096)
		if err != nil || string(cgroup) != s.cgroup {
			return nil, ErrIdentity
		}
	}
	return p.Engine, nil
}

func sameRoutedLANServiceFactsV1(a, b routedDHCPServerSocketFactsV1) bool {
	return slices.Equal(a.udp, b.udp) && slices.Equal(a.packet, b.packet)
}

// The grouped engine reconciles declared LocalServices separately. Check the
// actual DHCP listeners against the routed policy before giving it that view.
// A pending selected target can have closed DHCP until the Confirm inspection.
func (l *routedEmptyListenersV3) ObserveRouted(ctx context.Context, policy *routednft.Policy) ([]localpolicy.Listener, error) {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	actual, err := l.observeUnderV1(ctx)
	if err != nil {
		return nil, err
	}
	if len(actual) == 0 {
		if enabledRoutedLANV1(policy) && (!enabledRoutedLANV1(l.pendingLAN) ||
			policy.Network.Hash != l.pendingLAN.Network.Hash || !reflect.DeepEqual(policy.DHCPServer, l.pendingLAN.DHCPServer)) {
			return nil, ErrUnavailable
		}
		return nil, nil
	}
	if l.lan == nil || !l.lan.matches(policy) {
		return nil, ErrIdentity
	}
	return nil, nil
}

func (l *routedEmptyListenersV3) installLANV1(ctx context.Context, lan *routedLANServiceObservationV1) (bool, error) {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil || lan == nil {
		return false, ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lan != nil || !l.kernel.bound() || !lan.matches(l.pendingLAN) {
		return false, ErrIdentity
	}
	l.lan = lan
	wait := time.NewTicker(100 * time.Millisecond)
	defer wait.Stop()
	for ctx.Err() == nil {
		if _, err := l.observeUnderV1(ctx); err == nil {
			_, err := lan.proof(ctx, "server_accept")
			if err == nil {
				l.pendingLAN = nil
			}
			return true, err
		}
		select {
		case <-ctx.Done():
			return true, ErrUnavailable
		case <-wait.C:
		}
	}
	return true, ErrUnavailable
}

func (l *routedEmptyListenersV3) releaseLANV1(ctx context.Context) error {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.releaseLANUnderV1(ctx)
}

func (l *routedEmptyListenersV3) releaseLANUnderV1(ctx context.Context) error {
	lan := l.lan
	if lan == nil {
		return nil
	}
	if !lan.stopped {
		if _, err := lan.client.callServerV1(ctx, "server_stop", lan.work); err != nil {
			return err
		}
		lan.stopped = true
	}
	l.lan = nil
	if _, err := l.observeUnderV1(ctx); err != nil {
		l.lan = lan
		return err
	}
	return nil
}
