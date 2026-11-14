//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type routedDHCPJobAssemblyV4 struct {
	network      *routedNetworkSelectorV4
	listeners    localengine.Listeners
	target, host *os.File
	client       *routedDHCPJobClientV4
}

type routedDHCPJobsHelperV4 struct {
	mu           sync.Mutex
	assembly     routedDHCPJobAssemblyV4
	ctx          context.Context
	reader       *configpoc.RoutedSelectionReaderV2
	authority    configpoc.RoutedAuthorityV1
	integrity    *routedIntegrityGateV3
	readerGID    uint32
	runtime      *RoutedDHCPRuntimeV3
	owner        *RoutedDHCPDeferredReaderV4
	work         configpoc.RoutedWorkReferenceV1
	desired      string
	closeRuntime func() error
	cancel       context.CancelFunc
	done         chan struct{}
	failed       bool
}

func newRoutedDHCPJobsHelperV4(ctx context.Context, a routedDHCPJobAssemblyV4, reader *configpoc.RoutedSelectionReaderV2, authority configpoc.RoutedAuthorityV1, integrity *routedIntegrityGateV3, readerGID uint32) (*routedDHCPJobsHelperV4, error) {
	if ctx == nil || a.network == nil || a.listeners == nil || a.client == nil || a.target == nil || a.host == nil || reader == nil || authority == nil || integrity == nil || readerGID == 0 {
		return nil, ErrIdentity
	}
	h := &routedDHCPJobsHelperV4{assembly: a, ctx: ctx, reader: reader, authority: authority, integrity: integrity, readerGID: readerGID}
	a.network.beforeRestore = h.stopBeforeRestore
	return h, nil
}

func (h *routedDHCPJobsHelperV4) Inspect(ctx context.Context, selection configpoc.SelectionReferenceV2) (bool, error) {
	plan, err := h.reader.Resolve(ctx, selection, configpoc.SelectionResumeV2)
	if err != nil || !plan.Valid() || plan.Scope().Identity != h.authority.Identity() || (plan.Resolution() != "target" && plan.Resolution() != "before") {
		return false, ErrUnavailable
	}
	previous, bundle := plan.Bundles()
	if plan.Resolution() == "before" {
		if previous == nil {
			return false, ErrIdentity
		}
		bundle = *previous
	}
	if bundle.Firewall.Config.Routed == nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.runtime != nil || h.failed {
			return false, ErrUnavailable
		}
		return false, nil
	}
	desired, dhcp, err := routedNetworkProfileV4(bundle.Firewall.Config.Routed.Network)
	if err != nil {
		return false, err
	}
	if !dhcp {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.runtime != nil || h.failed {
			return false, ErrUnavailable
		}
		return false, nil
	}
	receipt, hash, err := h.authority.Observe(ctx)
	if err != nil || !integrityPhysicalIdleV3(receipt, hash) || hash != bundle.Composite.Hash {
		return false, ErrUnavailable
	}
	err = h.assembly.network.withDHCP(ctx, func(actual networkplan.Revision, lan *networkexecutor.LANBootstrapV3) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.failed || actual.Hash != desired.Hash {
			return ErrIdentity
		}
		if h.runtime != nil {
			if h.desired != desired.Hash {
				return ErrIdentity
			}
			return nil // Reader and actual LAN/lease were revalidated above.
		}
		listeners, e := h.assembly.listeners.Observe(ctx)
		if e != nil || len(listeners) != 0 {
			return ErrUnavailable
		}
		reply, files, e := h.assembly.client.call(ctx, "prepare", plan.Reference())
		if e != nil {
			h.failed = true
			return e
		}
		f := RoutedDHCPDeferredFilesV4{Request: files[0], Reply: files[1], ProducerPIDFD: files[2]}
		binding := *reply.Binding
		id := h.authority.Identity()
		if binding.Desired.Hash != desired.Hash || binding.Owner.Namespace != id.Namespace || binding.Owner.RunID != id.RunID || binding.Owner.BootID != id.BootID {
			_ = f.Close()
			h.failed = true
			return ErrIdentity
		}
		owner, e := NewRoutedDHCPDeferredReaderV4(f, binding)
		if e != nil {
			_ = f.Close()
			h.failed = true
			return e
		}
		lifetime, cancel := context.WithCancel(h.ctx)
		r, closeRuntime, e := assembleRoutedDHCPRuntimeV3(lifetime, RoutedDHCPRuntimeOptionsV3{LAN: lan, Target: h.assembly.target, Host: h.assembly.host, Desired: desired, Owner: binding.Owner, Current: owner.Current}, id, h.readerGID, h.reader, h.authority, h.integrity)
		if e != nil {
			cancel()
			_ = owner.Close()
			h.failed = true
			return e
		}
		h.runtime, h.owner, h.work, h.desired, h.closeRuntime, h.cancel = r, owner, plan.Reference(), desired.Hash, closeRuntime, cancel
		// Root repeats its selected preflight before privately confirming the real
		// acquisition PID. No grant can be read before that acknowledgement.
		if _, _, e = h.assembly.client.call(ctx, "activate", h.work); e != nil {
			h.failed = true
			return e
		}
		after, e := h.reader.Observe(ctx)
		if e != nil || after != selection {
			h.failed = true
			_ = h.assembly.client.Close()
			return ErrUnavailable
		}
		h.done = make(chan struct{})
		go func() { defer close(h.done); r.Run(lifetime) }()
		return nil
	})
	return err == nil, err
}

func (h *routedDHCPJobsHelperV4) Dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed || h.runtime == nil {
		return nil, ErrUnavailable
	}
	return h.runtime.dispatch(ctx, c)
}

func (h *routedDHCPJobsHelperV4) Invalidate(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed {
		_ = h.assembly.client.Close()
	}
	if h.runtime == nil {
		return nil
	}
	// Checking alone never closes a healthy lease. An authenticated incomplete
	// inspection does: close the effective token/forwarding, retain selected R2
	// evidence for normal retirement, and never fabricate an archival success.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	h.runtime.mu.Lock()
	defer h.runtime.mu.Unlock()
	return h.runtime.closeUnder(bounded)
}

// Called with selector ownership, before any baseline restoration. It refuses
// an outstanding selected WAN; the existing controller must retire that work.
func (h *routedDHCPJobsHelperV4) stopBeforeRestore(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runtime == nil {
		if h.failed {
			return ErrUnavailable
		}
		return nil
	}
	r := h.runtime
	r.mu.Lock()
	if r.work != "" || r.reader.VerifyDHCPReleasedV3(ctx) != nil {
		r.mu.Unlock()
		return configpoc.ErrRecovery
	}
	err := r.closeUnder(ctx)
	if err == nil && r.lease != nil {
		err = r.releaseLease(ctx)
		if err == nil {
			r.lease = nil
		}
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if _, _, err = h.assembly.client.call(ctx, "stop", h.work); err != nil {
		h.failed = true
		return err
	}
	h.cancel()
	if h.done != nil {
		<-h.done
	}
	err = errors.Join(h.closeRuntime(), h.owner.Close())
	if err != nil {
		h.failed = true
		return err
	}
	h.runtime = nil
	h.owner = nil
	h.work = configpoc.RoutedWorkReferenceV1{}
	h.desired = ""
	h.done = nil
	h.cancel = nil
	h.closeRuntime = nil
	return nil
}

func (h *routedDHCPJobsHelperV4) Close() error {
	// Whole-scope teardown owns drainage. No configuration is published here.
	_ = h.assembly.client.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failed = true
	if h.cancel != nil {
		h.cancel()
	}
	if h.done != nil {
		<-h.done
	}
	var err error
	if h.closeRuntime != nil {
		err = h.closeRuntime()
		h.closeRuntime = nil
	}
	if h.owner != nil {
		err = errors.Join(err, h.owner.Close())
		h.owner = nil
	}
	return err
}
