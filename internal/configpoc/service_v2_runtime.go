package configpoc

import (
	"context"
	"os"

	"github.com/AsterG/andeiva/internal/adminauth"
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
	manager, err := newReserveManagerV2(options.Pools.Admission, options.Pools.Plan, options.Pools.Emergency)
	if err != nil {
		return nil, err
	}
	trusted := v2CoordinatorOptions{Reserves: manager, GuardDeadlines: true, LocalPolicy: options.LocalPolicy}
	if options.BootID != "" {
		id := v2BootID(options.BootID)
		if !validBootIDV2(id) {
			return nil, ErrInvalid
		}
		trusted.BootID = &id
	}
	return openServiceCoordinatorV2(ctx, area, budget, auth, firewall, local, trusted)
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
	if domain != "firewall" {
		return CurrentV2{}, ErrDenied
	}
	return s.currentLocked(domain)
}
