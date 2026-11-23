//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const RoutedActivationPreparedRoleV1 = "--andeiva-routed-activation-prepared-v1"

type activationPreparedRequestV1 struct {
	Version    int
	Parent     int
	IDs        Identities
	Deployment []byte
	Expected   configpoc.PreparedActivationExpectationV1
}

func readActivationPreparedV1(ctx context.Context, ids Identities, artifacts activationArtifactsV1) (configpoc.PreparedActivationInspectionV1, error) {
	var proof configpoc.PreparedActivationInspectionV1
	record, err := decodeRoutedDeploymentV3(artifacts.deployment, ids)
	if err != nil {
		return proof, err
	}
	ctx, cancel := context.WithTimeout(ctx, configpoc.IntegrityInspectionDeadlineV1)
	defer cancel()
	cmd, err := activationChildV1(ctx, RoutedActivationPreparedRoleV1, ids.HelperUID, ids.IPCGID, record.Access[0].ReaderGID)
	if err != nil {
		return proof, err
	}
	request := marshal(activationPreparedRequestV1{Version: 1, Parent: os.Getpid(), IDs: ids, Deployment: artifacts.deployment, Expected: artifacts.expected})
	if len(request) > 65536 {
		return proof, ErrConfiguration
	}
	cmd.Stdin = bytes.NewReader(request)
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if cmd.Run() != nil || ctx.Err() != nil || routedPrivateDecodeV4(output.Bytes(), &proof) != nil ||
		!routedPrivateHashV4(proof.Startup) || !routedPrivateHashV4(proof.Selection.Selection) || proof.Selection.Sequence == 0 {
		return configpoc.PreparedActivationInspectionV1{}, ErrUnavailable
	}
	return proof, nil
}

func RunRoutedActivationPreparedRoleV1(ctx context.Context) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if checkMigrationWorkerFDsV3(2) != nil {
		return ErrIdentity
	}
	limit := configpoc.IntegrityInspectionDeadlineV1
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	control, err := migrationFingerprintControlV3(limit)
	if err != nil {
		return err
	}
	defer control.Close()
	raw, err := io.ReadAll(io.LimitReader(control, 65537))
	var request activationPreparedRequestV1
	if err != nil || len(raw) > 65536 || routedPrivateDecodeV4(raw, &request) != nil || request.Version != 1 ||
		request.Parent <= 1 || request.Parent != os.Getppid() {
		return ErrIdentity
	}
	record, err := decodeRoutedDeploymentV3(request.Deployment, request.IDs)
	if err != nil {
		return err
	}
	if err = authenticateActivationReaderV1(request.Parent, request.IDs, record.Access[0].ReaderGID); err != nil {
		return err
	}
	resources := &routedDeploymentResourcesV3{}
	defer func() { result = errors.Join(result, resources.Close()) }()
	if err = resources.openPreparedStore(record); err != nil {
		return err
	}
	launch := resources.launch
	var pools [3]*recoveryreserve.ReadOnlyPoolV2
	defer func() {
		for _, pool := range pools {
			if pool != nil {
				result = errors.Join(result, pool.Close())
			}
		}
	}()
	for i, resource := range []RoutedReaderRootV3{launch.Admission, launch.Plan, launch.Emergency} {
		pools[i], err = recoveryreserve.OpenReadOnlyV2(resource.Root, resource.Access, resource.Profile)
		if err != nil {
			return err
		}
	}
	proof, err := configpoc.InspectPreparedActivationV1(ctx, launch.Store.Root, configpoc.SelectionReaderOptionsV2{
		Access: launch.Store.Access, Admission: pools[0], Plan: pools[1], Emergency: pools[2],
		Budget: record.ReadBudget.budget(),
	}, request.Expected)
	if err != nil {
		return err
	}
	return routedPrivateWriteV4(os.Stdout, proof)
}

func authenticateActivationReaderV1(parent int, ids Identities, readerGID uint32) error {
	status, err := routedDHCPOwnerReadV3("/proc/self/status", 65536)
	groups, groupErr := os.Getgroups()
	if err != nil || groupErr != nil || !matchesIdentity(os.Getuid(), ids.HelperUID) || !matchesIdentity(os.Geteuid(), ids.HelperUID) ||
		!matchesIdentity(os.Getgid(), ids.IPCGID) || !matchesIdentity(os.Getegid(), ids.IPCGID) ||
		privilegeFields(string(status), false) != nil || len(groups) != 1 || !matchesIdentity(groups[0], readerGID) {
		return ErrIdentity
	}
	root, err := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(parent)+"/status", 65536)
	if err != nil || !rootRoutedParentStatusV3(root, parent) {
		return ErrIdentity
	}
	return armMigrationParentDeathV3(parent)
}
