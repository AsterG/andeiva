//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const routedDHCPServerReplyMarginV1 = 500 * time.Millisecond

type routedDHCPServerJobProofV1 struct {
	Version int                               `json:"version"`
	RolePID int                               `json:"role_pid"`
	UID     uint32                            `json:"uid"`
	Cgroup  RoutedDHCPServiceCgroupIdentityV1 `json:"cgroup"`
	Links   []routedDHCPServerSelectedLinkV1  `json:"links"`
	Engine  *routedKeaSocketProofV1           `json:"engine,omitempty"`
}

type routedDHCPServerJobsV1 struct {
	options       routedDHCPServerSelectedOptionsV1
	lifetime      context.Context
	owner         *routedDHCPServerSelectedLaunchV1
	work          configpoc.RoutedWorkReferenceV1
	cancelStartup context.CancelFunc
	ready         bool
	probed        bool
}

func (p *routedDHCPServerJobProofV1) validV1(op string) bool {
	if p == nil || p.Version != 1 || p.RolePID <= 1 || p.RolePID > math.MaxInt32 || p.UID == 0 ||
		p.Cgroup.Device == 0 || p.Cgroup.Inode == 0 || len(p.Links) == 0 || len(p.Links) > 32 {
		return false
	}
	names, indices, addresses := make(map[string]bool), make(map[uint32]bool), make(map[netip.Addr]bool)
	for _, link := range p.Links {
		mac, err := net.ParseMAC(link.MAC)
		if !device.MatchString(link.Name) || names[link.Name] || link.Index == 0 || indices[link.Index] ||
			err != nil || len(mac) != 6 || mac.String() != link.MAC || !link.Address.IsValid() ||
			!link.Address.Addr().Is4() || !link.Address.Addr().IsGlobalUnicast() || addresses[link.Address.Addr()] {
			return false
		}
		names[link.Name], indices[link.Index], addresses[link.Address.Addr()] = true, true, true
	}
	engine := p.Engine
	if op == "server_start" {
		return engine == nil
	}
	return engine != nil && !engine.Unavailable && engine.Query.Version == 1 && engine.Query.Sequence > 0 &&
		engine.PID > 1 && engine.PID != p.RolePID && engine.PID <= math.MaxInt32 && engine.Start > 0 &&
		len(engine.Inodes) > 0 && len(engine.Inodes) <= 256 && engine.Inodes[0] != 0 && slices.IsSorted(engine.Inodes)
}

func routedDHCPServerJobValidV1(q routedDHCPJobV4, m Metadata, last uint64) bool {
	if q.Version != 6 || q.DeadlineBootNS <= 0 {
		return false
	}
	switch q.Operation {
	case "server_start", "server_observe", "server_accept", "server_stop":
	default:
		return false
	}
	q.Version, q.Operation, q.DeadlineBootNS = 4, "prepare", 0
	return routedDHCPJobValidV4(q, m, last)
}

// The authenticated helper invokes these operations only from an inspection
// that retains the coordinator's publication barrier across the full exchange.
func (b *routedDHCPServerJobsV1) dispatch(ctx context.Context, q routedDHCPJobV4) (*routedDHCPServerJobProofV1, error) {
	if b == nil || ctx == nil || ctx.Err() != nil || b.lifetime == nil || b.lifetime.Err() != nil {
		return nil, ErrUnavailable
	}
	now, err := routedDHCPOwnerBootNowV3()
	if err != nil || q.DeadlineBootNS <= now || q.DeadlineBootNS-now > int64(configpoc.IntegrityInspectionDeadlineV1) {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(q.DeadlineBootNS-now))
	defer cancel()
	if q.Operation == "server_stop" {
		if b.owner == nil || b.work != q.Work {
			return nil, ErrIdentity
		}
		return nil, b.stop(ctx)
	}
	if q.Operation == "server_start" {
		if b.owner != nil {
			return nil, ErrUnavailable
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, ErrIdentity
		}
		// This call ends before the helper's two kernel samples. The original
		// setup deadline and supervisor lifetime still cover those samples.
		startup, cancel := context.WithDeadline(b.lifetime, deadline)
		b.cancelStartup = cancel
		b.work = q.Work
		b.options.socketProof = true
		var err error
		b.owner, err = startRoutedDHCPServerSelectedV1(startup, b.lifetime, b.options, q.Work)
		if err != nil {
			cancel()
			return nil, errors.Join(err, b.stop(ctx))
		}
		proof, err := b.proof(ctx, false)
		if err != nil {
			return nil, errors.Join(err, b.stop(ctx))
		}
		return proof, nil
	}
	if b.owner == nil || b.work != q.Work || b.owner.launch == nil {
		return nil, ErrIdentity
	}
	switch q.Operation {
	case "server_observe":
		proof, err := b.proof(ctx, true)
		b.probed = err == nil
		return proof, err
	case "server_accept":
		if b.ready || !b.probed {
			return nil, ErrIdentity
		}
		proof, err := b.proof(ctx, true)
		if err != nil {
			return nil, err
		}
		if err := b.owner.launch.acceptStartupV2(); err != nil {
			return nil, err
		}
		b.ready = true
		b.cancelStartup()
		return proof, nil
	default:
		return nil, ErrIdentity
	}
}

func (b *routedDHCPServerJobsV1) proof(ctx context.Context, engine bool) (*routedDHCPServerJobProofV1, error) {
	owner := b.owner
	if owner == nil || !owner.launch.Alive() {
		return nil, ErrUnavailable
	}
	selected := owner.selected
	if !b.ready {
		current, err := b.options.readSelected(ctx, b.work)
		if err != nil || current.Reference != selected.Reference || current.Bundle.Composite.Hash != selected.Bundle.Composite.Hash {
			return nil, ErrIdentity
		}
	}
	// Once accepted, the reply proves the retained process and its sockets.
	// A newly selected configuration cannot change those facts or inherit them.
	plan, err := routedDHCPServerBindingPlanFromSelectedV1(selected, b.options.identity, b.work)
	if err != nil {
		return nil, err
	}
	links, err := readRoutedDHCPServerSelectedLinksV1(ctx, b.options.metadata, b.options.gateway, b.options.host, plan)
	if err != nil || !slices.Equal(links, owner.links) {
		return nil, ErrIdentity
	}
	uid, _, err := routedDHCPServerAccountV1()
	if err != nil {
		return nil, err
	}
	proof := &routedDHCPServerJobProofV1{Version: 1, RolePID: owner.launch.PID(), UID: uid, Cgroup: owner.lan, Links: links}
	if engine {
		observed, err := owner.launch.inspectSocketsV3(ctx)
		if err != nil {
			return nil, err
		}
		proof.Engine = &observed
	}
	return proof, nil
}

// Run only from supervisor-owned inspection. Let a sent request finish over
// the shared channel even if the originating management caller disconnects.
func (c *routedDHCPJobClientV4) callServerV1(ctx context.Context, op string, work configpoc.RoutedWorkReferenceV1) (*routedDHCPServerJobProofV1, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	deadline := time.Now().Add(configpoc.IntegrityInspectionDeadlineV1)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	call, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	reply, files, err := c.callVersion(call, 6, op, work)
	for _, f := range files {
		_ = f.Close()
	}
	return reply.Server, err
}

func (b *routedDHCPServerJobsV1) stop(ctx context.Context) error {
	if b == nil || b.owner == nil {
		return nil
	}
	if b.cancelStartup != nil {
		b.cancelStartup()
	}
	if err := b.owner.stopV1(ctx); err != nil {
		return err
	}
	b.owner, b.cancelStartup = nil, nil
	b.work, b.ready, b.probed = configpoc.RoutedWorkReferenceV1{}, false, false
	return nil
}

func (b *routedDHCPServerJobsV1) close() error {
	if b == nil || b.owner == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), routedDHCPServerStopGraceV1+3*time.Second)
	defer cancel()
	if err := b.stop(ctx); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}
