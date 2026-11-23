//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type routedDHCPServerSelectedOptionsV1 struct {
	metadata                 Metadata
	identity                 networkexecutor.OwnedNamespaceIdentity
	gateway, host, hostMount *os.File
	runtime                  *os.Root
	registry, leases         *os.File
	leaseBudget              int64
	services                 *RoutedDHCPServerServiceSetV1
	socketProof              bool
	requestBoundCleanup      bool
	readSelected             func(context.Context, configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error)
}

// The root broker serializes this owner with withdrawals of the selected work
// and stops it before releasing the service leaf or the operational storage.
type routedDHCPServerSelectedLaunchV1 struct {
	launch   *RoutedDHCPServerLaunchV1
	artifact *routedDHCPServerSelectedArtifactV1
	services *RoutedDHCPServerServiceSetV1
	selected RoutedSelectedPreflightResultV4
	links    []routedDHCPServerSelectedLinkV1
	lan      RoutedDHCPServiceCgroupIdentityV1
}

// The caller retains the existing InspectRuntimeV1 publication barrier until
// readiness is verified and accepted, or until the role has been retired.
func startRoutedDHCPServerSelectedV1(ctx, lifetime context.Context, o routedDHCPServerSelectedOptionsV1, work configpoc.RoutedWorkReferenceV1) (owner *routedDHCPServerSelectedLaunchV1, result error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || o.services == nil ||
		o.readSelected == nil || o.metadata.ValidateRouted() != nil || o.identity.RunID != o.metadata.RunID ||
		o.identity.BootID != o.metadata.BootID || o.identity.Namespace != o.metadata.GatewayNamespace || o.identity.Host != o.metadata.HostNamespace {
		return nil, ErrIdentity
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrIdentity
	}
	selected, err := o.readSelected(ctx, work)
	if err != nil {
		return nil, err
	}
	plan, err := routedDHCPServerBindingPlanFromSelectedV1(selected, o.identity, work)
	if err != nil {
		return nil, err
	}
	links, err := readRoutedDHCPServerSelectedLinksV1(ctx, o.metadata, o.gateway, o.host, plan)
	if err != nil {
		return nil, err
	}
	pins, err := o.services.ReadOnlyPinsV1()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, pin := range pins {
			_ = pin.Directory.Close()
		}
	}()
	var lan *os.File
	var laneIdentity RoutedDHCPServiceCgroupIdentityV1
	for _, pin := range pins {
		if pin.Role == "lan" {
			lan = pin.Directory
			laneIdentity = pin.Identity
		}
	}
	if lan == nil {
		return nil, ErrIdentity
	}
	cgroup, err := routedDHCPServiceReadAtV1(lan, "cgroup.procs", 4096)
	if err != nil || len(cgroup) != 0 {
		return nil, ErrUnavailable
	}

	artifact, err := compileRoutedDHCPServerSelectedArtifactV1(ctx, o.identity, work, selected, o.runtime, o.registry, o.leases, o.leaseBudget)
	if err != nil {
		return nil, err
	}
	active := &routedDHCPServerSelectedLaunchV1{
		artifact: artifact, services: o.services, selected: selected, links: links, lan: laneIdentity,
	}
	attempted := false
	defer func() {
		if result != nil {
			if !attempted {
				result = errors.Join(result, artifact.closeV1())
				return
			}
			cleanup := ctx
			if !o.requestBoundCleanup {
				var cancel context.CancelFunc
				cleanup, cancel = context.WithTimeout(context.WithoutCancel(lifetime), routedDHCPServerStopGraceV1+3*time.Second)
				defer cancel()
			}
			if err := active.stopV1(cleanup); err != nil {
				// A caller must retain this owner and fence further starts if
				// the LAN leaf or its config cannot be verified retired.
				owner = active
				result = errors.Join(result, err)
			}
		}
	}()
	recheck := func() error {
		after, err := o.readSelected(ctx, work)
		if err != nil || after.Reference != selected.Reference || after.Work != selected.Work ||
			after.Bundle.Composite.Hash != selected.Bundle.Composite.Hash || routedPreflightResultV4(after, RoutedPreflightDHCPServerV1, o.identity, work) != nil {
			return ErrIdentity
		}
		actual, err := readRoutedDHCPServerSelectedLinksV1(ctx, o.metadata, o.gateway, o.host, plan)
		if err != nil || ctx.Err() != nil || !slices.Equal(actual, links) {
			return ErrIdentity
		}
		return nil
	}
	if err := recheck(); err != nil {
		return nil, err
	}
	attempted = true
	active.launch, err = startRoutedDHCPServerScopedV2(ctx, lifetime, RoutedDHCPServerResourcesV1{
		Metadata: o.metadata, Gateway: o.gateway, Host: o.host, HostMount: o.hostMount,
		Configuration: artifact.file, Leases: o.leases, Config: artifact.config, Bindings: artifact.bindings,
		ServiceCgroups: pins, LeaseBudgetBytes: o.leaseBudget,
		socketProof: o.socketProof, requestBoundCleanup: o.requestBoundCleanup,
	})
	if err != nil {
		return nil, err
	}
	if err := recheck(); err != nil {
		return nil, err
	}
	return active, nil
}

func (s *routedDHCPServerSelectedLaunchV1) stopV1(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var stopErr error
	if s.launch != nil {
		stopErr = s.launch.Stop(ctx)
	}
	if err := s.services.DrainFeatureV1(ctx, "lan"); err != nil {
		// Retain the config pin after an uncertain drain for root recovery.
		return errors.Join(stopErr, err)
	}
	if stopErr != nil {
		if retryErr := s.launch.Stop(ctx); retryErr != nil {
			return errors.Join(stopErr, retryErr)
		}
	}
	s.launch = nil
	return s.artifact.closeV1()
}
