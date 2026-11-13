package configpoc

import (
	"context"
	"os"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// RuntimePoolsV2 are already opened, installer-owned pools. This constructor
// neither prepares storage nor derives resources from administrative input.
type RuntimePoolsV2 struct {
	Admission *recoveryreserve.PoolV2
	Plan      *recoveryreserve.PoolV2
	Emergency *recoveryreserve.PoolV2
}
type RuntimeOptionsV2 struct {
	DHCPRecovery   RoutedDHCPRecoveryV3
	Integrity      RuntimeIntegrityV1
	SharedReader   *recoveryreserve.ReaderAccessV2
	Routed         RoutedAuthorityV1
	RoutedIdentity networkexecutor.OwnedNamespaceIdentity
	Pools          RuntimePoolsV2
	GuardDeadlines bool
	BootID         string
	LocalPolicy    LocalPolicyV2
}

// OpenRuntimeServiceV2 consumes only the selected v2 store. It never opens a
// legacy writer or creates a second database. Pool handles remain caller-owned.
func OpenRuntimeServiceV2(ctx context.Context, area *os.Root, budget BudgetV2, auth *adminauth.Manager, firewall, local []Engine, options RuntimeOptionsV2) (*ServiceV2, error) {
	if !options.GuardDeadlines || options.Pools.Admission == nil || options.Pools.Plan == nil || options.Pools.Emergency == nil {
		return nil, ErrInvalid
	}
	if options.Integrity != nil && (options.Routed == nil || options.SharedReader == nil || options.BootID == "") {
		return nil, ErrInvalid
	}
	manager, err := newReserveManagerV2(options.Pools.Admission, options.Pools.Plan, options.Pools.Emergency)
	if err != nil {
		return nil, err
	}
	if options.Routed != nil && (!validRoutedIdentityV1(options.RoutedIdentity) || options.Routed.Identity() != options.RoutedIdentity) {
		return nil, ErrInvalid
	}
	trusted := v2CoordinatorOptions{Integrity: options.Integrity, SharedReader: options.SharedReader, Reserves: manager, GuardDeadlines: true, LocalPolicy: options.LocalPolicy, Routed: options.Routed, RoutedIdentity: options.RoutedIdentity}
	trusted.DHCPRecovery = options.DHCPRecovery
	if options.BootID != "" {
		id := v2BootID(options.BootID)
		if !validBootIDV2(id) {
			return nil, ErrInvalid
		}
		trusted.BootID = &id
	}
	return openServiceCoordinatorV2(ctx, area, budget, auth, firewall, local, trusted)
}

// PrepareRoutedCompositeV1 is a trusted cold cutover, never an HTTP operation.
// Assembly must already supply the exclusive typed group authority and pools.
func (s *ServiceV2) PrepareRoutedCompositeV1(ctx context.Context) error {
	if s == nil || s.coordinator == nil || s.coordinator.options.Routed == nil {
		return ErrDenied
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.prepareRoutedCompositeLockedV2(ctx, v2ReachabilityBudget{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128})
}

// PrepareRuntimeReservesV2 is an explicit installer migration on this service's
// sole writer. It allocates no pool and accepts no administrative request data.
func (s *ServiceV2) PrepareRuntimeReservesV2(ctx context.Context, pools RuntimePoolsV2) error {
	if s == nil || s.coordinator == nil || ctx == nil {
		return ErrInvalid
	}
	manager, err := newReserveManagerV2(pools.Admission, pools.Plan, pools.Emergency)
	if err != nil {
		return err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if ctx.Err() != nil || c.closed || c.store.blocked || c.store.state.Configuration == nil {
		return ErrRecovery
	}
	state := c.store.state.Configuration
	if state.Intent != nil || state.Pending != nil || state.RecoveryRequired || state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil || len(c.store.state.ActiveReserves) != 0 || c.store.state.SystemBundle != nil {
		return ErrConflict
	}
	for _, namespace := range c.store.state.Namespaces {
		if len(namespaceOpenIDsV2(namespace)) != 0 {
			return ErrConflict
		}
	}
	if !c.readback(*state) || manager.verifySelected(c.store) != nil {
		return ErrRecovery
	}
	if err := c.store.enableClosingCreditsLocked(); err != nil {
		return err
	}
	c.store.reserves, c.options.Reserves = manager, manager
	return nil
}

// AuthenticatedBy prevents assembling a router and coordinator with unrelated
// session authorities; it exposes no session data or authentication primitive.
func (s *ServiceV2) AuthenticatedBy(auth *adminauth.Manager) bool {
	return s != nil && auth != nil && s.auth == auth
}

// Current observes global and domain state under the same store lock. Viewer
// access remains read-only and account incarnation is checked server-side.
func (s *ServiceV2) Current(binding adminauth.SessionBinding, domain string) (CurrentV2, error) {
	p, err := s.principal(binding)
	if err != nil {
		return CurrentV2{}, err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked {
		return CurrentV2{}, errV2Unavailable
	}
	if !c.store.principalV2Locked(p) || (p.Role != RoleAdmin && p.Role != RoleViewer) {
		return CurrentV2{}, ErrDenied
	}
	if domain == "" {
		domain = "firewall"
		if hasFeatureV2(c.store.state, v2RoutedFeature) {
			domain = "routed"
		}
	}
	if !c.store.observableDomainV2(domain) {
		return CurrentV2{}, ErrDenied
	}
	return s.currentLocked(domain)
}
