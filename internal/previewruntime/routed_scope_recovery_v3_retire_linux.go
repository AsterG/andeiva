//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Only managed Root calls this path with authenticated inherited anchors and
// the already verified deployment cutover. It never accepts public proof DTOs.
func retireInheritedRoutedScopeV3(ctx context.Context, c Config, area *os.Root, slot *routedRetirementSlot, record *routedScopeRecordSlotV3, r *RoutedScopeRecoveryV3, ids Identities) (result error) {
	if ctx == nil || ctx.Err() != nil || r == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	deployment, err := openRoutedRecoveryDeploymentV3(ctx, c, r.record.Metadata, ids)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, deployment.Close()) }()
	return retireInheritedRoutedScopeResourcesV3(ctx, area, slot, record, r, ids, deployment.launch)
}

// The deployment wrapper above is the only production caller. Native component
// tests supply real pinned reader resources without claiming deployment provenance.
func retireInheritedRoutedScopeResourcesV3(ctx context.Context, area *os.Root, slot *routedRetirementSlot, record *routedScopeRecordSlotV3, r *RoutedScopeRecoveryV3, ids Identities, resources RoutedLaunchResourcesV3) (result error) {
	if ctx == nil || ctx.Err() != nil || area == nil || slot == nil || record == nil || r == nil || os.Getuid() != 0 || os.Geteuid() != 0 || r.record.Identities != ids {
		return ErrIdentity
	}
	if resources.Metadata != r.record.Metadata || resources.Identities != ids {
		return ErrIdentity
	}
	raw, err := record.read()
	if err != nil {
		return err
	}
	actual, err := DecodeRoutedScopeRecoveryV3(raw)
	if err != nil || actual != r.record {
		return ErrIdentity
	}
	observed, err := record.reader.Stat()
	if err != nil {
		return err
	}
	held, err := r.files[0].Stat()
	if err != nil || !os.SameFile(observed, held) {
		return ErrIdentity
	}
	if err = r.VerifyStored(ctx); err != nil {
		return err
	}
	barrier, err := openScopeRecoveryBarrierV3(ctx, resources.Store, ids)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, barrier.Close()) }()
	old := networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: r.record.Metadata.GatewayNamespace, Host: r.record.Metadata.HostNamespace, BootID: r.record.Metadata.BootID, RunID: r.record.Metadata.RunID}
	options := RoutedSelectedPreflightOptionsV4{Metadata: r.record.Metadata, Identities: ids, Store: resources.Store, Admission: resources.Admission, Plan: resources.Plan, Emergency: resources.Emergency, Budget: resources.Budget, Identity: old, Purpose: RoutedPreflightRetirementV4}
	source, err := ReadRoutedSelectedPreflightV4(ctx, options)
	if err != nil {
		return err
	}
	if source.Identity != old || routedPreflightResultV4(source, RoutedPreflightRetirementV4, old, configpoc.RoutedWorkReferenceV1{}) != nil {
		return ErrIdentity
	}
	checkSelected := func() error {
		if err := barrier.check(ctx); err != nil {
			return err
		}
		next, err := ReadRoutedSelectedPreflightV4(ctx, options)
		if err != nil || next.Identity != old || next.Reference != source.Reference || routedPreflightResultV4(next, RoutedPreflightRetirementV4, old, configpoc.RoutedWorkReferenceV1{}) != nil {
			return ErrIdentity
		}
		return barrier.check(ctx)
	}
	if err = r.checkDrainedV3(ctx); err != nil {
		return err
	}
	cleanup, err := prepareScopeRecoveryCleanupV3(area, r.record)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, cleanup.Close()) }()
	if err = checkSelected(); err != nil {
		return err
	}
	if err = closeScopeRecoveryNetworkV3(ctx, func(call context.Context, op scopeRecoveryNetworkOpV3) ([]byte, error) {
		return runScopeRecoveryNetworkV3(call, r.files[1], r.record.Metadata, op)
	}); err != nil {
		return err
	}
	if err = r.checkDrainedV3(ctx); err != nil {
		return err
	}
	if err = checkSelected(); err != nil {
		return err
	}
	if err = r.detachNamespaceV3(ctx); err != nil {
		return err
	}
	if err = cleanup.removeChildren(); err != nil {
		return err
	}
	if err = checkSelected(); err != nil {
		return err
	}
	if err = waitRoutedCgroupDrainedV3(); err != nil {
		return err
	}
	if err = r.DropStored(ctx); err != nil {
		return err
	}
	if err = r.Close(); err != nil {
		return err
	}
	if err = barrier.check(ctx); err != nil {
		return err
	}
	if err = slot.recordDrained(r.record.Metadata, ids); err != nil {
		return err
	}
	if err = cleanup.removeMetadata(); err != nil {
		return err
	}
	return record.clearCompleted(ctx, slot)
}
