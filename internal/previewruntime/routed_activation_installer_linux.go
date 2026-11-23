//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

// This is the measured initial Preview profile. The production admission and
// retention policy must qualify separately before a grouped service release.
var activationPreviewBudgetV1 = routedReadBudgetV3{
	Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000,
	Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128,
}

const activationConfigDirV1 = "/etc/andeiva-preview"
const activationSocketConfigV1 = "/etc/systemd/system/andeiva-preview-grouped.socket.d/listen.conf"

// ActivateRoutedMigrationV1 is an explicit offline installer entry point. A
// failed prepublication attempt never enables either runtime. The classical
// startup masks persist across reboot; the grouped masks remain until the
// source worker releases successfully and the published marker is verified.
func ActivateRoutedMigrationV1(ctx context.Context, c Config) (proof configpoc.PreparedActivationInspectionV1, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil ||
		ownedDirectory(activationConfigDirV1, 0, 0, 0755) != nil || ownedDirectory(DataDir, 0, 0, 0755) != nil {
		return proof, ErrIdentity
	}
	config, err := os.OpenRoot(activationConfigDirV1)
	if err != nil {
		return proof, ErrStorage
	}
	defer config.Close()
	lock, err := config.Open(".")
	if err != nil {
		return proof, ErrStorage
	}
	defer lock.Close()
	if !fenceNoACLV3(lock, true) || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return proof, ErrUnavailable
	}
	data, err := os.OpenRoot(DataDir)
	if err != nil {
		return proof, ErrStorage
	}
	defer data.Close()
	if _, err = data.Lstat("grouped-cutover.json"); !errors.Is(err, os.ErrNotExist) {
		return proof, ErrConfiguration
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		return proof, err
	}
	inputs, err := readActivationEvidenceV1(ids)
	if err != nil {
		return proof, err
	}
	artifacts, err := buildActivationArtifactsV1(inputs, ids, activationPreviewBudgetV1)
	if err != nil {
		return proof, err
	}
	node, err := decodeRoutedNodeLinksV3(inputs.links)
	if err != nil || activationHostClosedV1(node) != nil || checkActivationParentsV1(node) != nil {
		return proof, ErrIdentity
	}
	if _, err = loadTLS(c, ids); err != nil {
		return proof, err
	}
	listen, err := readOwned(activationSocketConfigV1, 0, 0, 0644, 4096)
	if err != nil || !bytes.Equal(listen, socketConfiguration(c)) {
		return proof, ErrConfiguration
	}
	phase := "exclude"
	slog.Info("grouped activation requested")
	defer func() {
		if result != nil {
			slog.Warn("grouped activation stopped", "phase", phase)
		}
	}()
	if err = excludeActivationWritersV1(ctx); err != nil {
		return proof, err
	}
	phase = "source_lock"
	err = withActivationSourceV1(ctx, ids, artifacts.expected.Firewall, func(ctx context.Context) error {
		phase = "prepare_runtime"
		if err := prepareActivationRuntimeV1(ctx, c, ids, config, artifacts); err != nil {
			return err
		}
		phase = "inspect_prepared"
		proof, err = readActivationPreparedV1(ctx, ids, artifacts)
		if err != nil {
			return err
		}
		current, err := readActivationEvidenceV1(ids)
		if err != nil || !sameActivationEvidenceV1(inputs, current) || ensureActivationExclusionV1(ctx) != nil ||
			activationHostClosedV1(node) != nil || checkActivationParentsV1(node) != nil {
			return ErrConfiguration
		}
		manifest, err := readOwned(routedDeploymentPathV3, 0, 0, 0600, 16384)
		if err != nil || !bytes.Equal(manifest, artifacts.deployment) {
			return ErrConfiguration
		}
		listener, err := readOwned(activationSocketConfigV1, 0, 0, 0644, 4096)
		if err != nil || !bytes.Equal(listener, listen) {
			return ErrConfiguration
		}
		if err = prepareActivationIntegrityV1(ctx, ids); err != nil {
			return err
		}
		phase = "source_recheck"
		return nil
	}, func(ctx context.Context, sourceStillAlive func() error) error {
		phase = "publish_marker"
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		return publishActivationRecordCheckedV1(data, "grouped-cutover.json", artifacts.cutover, sourceStillAlive)
	})
	if err != nil {
		return configpoc.PreparedActivationInspectionV1{}, err
	}
	marker, err := readOwned(routedCutoverPathV3, 0, 0, 0600, 4096)
	if err != nil || !bytes.Equal(marker, artifacts.cutover) || verifyRoutedCutoverV3(marker, artifacts.deployment, inputs.links) != nil {
		return configpoc.PreparedActivationInspectionV1{}, ErrIdentity
	}
	phase = "startup"
	if err = startActivatedRuntimeV1(ctx, c); err != nil {
		// Cancellation must still allow the ownership-bound supervisor to
		// drain the grouped scope before any retry or maintenance.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 55*time.Second)
		defer cancel()
		_, maskErr := activationSystemctlV1(cleanup, "mask", activationGroupedUnitsV1...)
		_, stopErr := activationSystemctlV1(cleanup, "stop", activationGroupedUnitsV1...)
		return configpoc.PreparedActivationInspectionV1{}, errors.Join(err, maskErr, stopErr, ensureActivationExclusionV1(cleanup), syncDirectory("/etc/systemd/system"))
	}
	slog.Info("grouped activation verified")
	return proof, nil
}

func prepareActivationRuntimeV1(ctx context.Context, c Config, ids Identities, config *os.Root, artifacts activationArtifactsV1) error {
	if _, err := config.Lstat("grouped.json"); errors.Is(err, os.ErrNotExist) {
		if err = publishActivationRecordV1(config, "grouped.json", artifacts.deployment); err != nil {
			return err
		}
	} else if err != nil {
		return ErrStorage
	}
	manifest, err := readOwned(routedDeploymentPathV3, 0, 0, 0600, 16384)
	if err != nil || !bytes.Equal(manifest, artifacts.deployment) {
		return ErrIdentity
	}
	operational, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return ErrStorage
	}
	defer operational.Close()
	if _, err = operational.Lstat(routedRetirementSlotV3); err != nil {
		return ErrStorage
	}
	retirement, err := openRoutedRetirementSlotV3(operational)
	if err != nil {
		return err
	}
	defer retirement.Close()
	scope, err := openScopeRecordSlotV3(operational, false)
	if err != nil {
		return err
	}
	defer scope.Close()
	scopeData, err := scope.read()
	if err != nil || !scopeRecordZeroV3(scopeData) || ctx.Err() != nil {
		return ErrConfiguration
	}
	// A prepared first activation does not have an earlier live scope.
	retired := make([]byte, RootRetirementReceiptSizeV3)
	if _, err = retirement.file.ReadAt(retired, 0); err != nil || !bytes.Equal(retired, make([]byte, len(retired))) {
		return ErrConfiguration
	}
	if _, err = loadTLS(c, ids); err != nil {
		return err
	}
	return nil
}

func prepareActivationIntegrityV1(ctx context.Context, ids Identities) error {
	parent, err := os.OpenRoot(routedDeploymentDataV3)
	if err != nil {
		return ErrStorage
	}
	defer parent.Close()
	if ownedDirectory(routedDeploymentDataV3, 0, 0, 0755) != nil {
		return ErrIdentity
	}
	if err = parent.Mkdir("integrity", 0700); err == nil {
		if err = parent.Chown("integrity", int(ids.HelperUID), int(ids.IPCGID)); err != nil {
			return ErrStorage
		}
		if err = syncDirectory(routedDeploymentDataV3); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return ErrStorage
	}
	resources := &routedDeploymentResourcesV3{}
	defer resources.Close()
	area, err := resources.openPinnedRoot(routedDeploymentDataV3 + "/integrity")
	if err != nil {
		return err
	}
	dir, err := area.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if validateRoutedIntegrityDirectoryV3(dir, ids.HelperUID, ids.IPCGID, nil) != nil {
		return ErrIdentity
	}
	if _, err = area.Lstat(routedIntegrityFenceNameV3); errors.Is(err, os.ErrNotExist) {
		if err = PrepareRoutedIntegrityLaunchV3(ctx, ids, area, nil); err != nil {
			return err
		}
	} else if err != nil {
		return ErrStorage
	}
	// The grouped helper is masked. Read the preparer's exact unblocked
	// record, never clear or repair a partial marker on a retry.
	const path = routedDeploymentDataV3 + "/integrity/" + routedIntegrityFenceNameV3
	payload, err := readOwned(path, ids.HelperUID, ids.IPCGID, 0600, routedIntegrityFenceSizeV3)
	expected := make([]byte, routedIntegrityFenceSizeV3)
	copy(expected, routedIntegrityFenceHeaderV3)
	if err != nil || !bytes.Equal(payload, expected) {
		return ErrStorage
	}
	return nil
}

func readActivationEvidenceV1(ids Identities) (e activationEvidenceV1, err error) {
	for _, file := range []struct {
		path  string
		data  *[]byte
		group uint32
		mode  os.FileMode
		size  int64
	}{
		{routedMigrationPlanPathV3, &e.draft, 0, 0600, 65536},
		{routedMigrationAuthorizationPathV3, &e.authorization, 0, 0600, 65536},
		{migrationPreparedPathV3, &e.prepared, 0, 0600, 16384},
		{routedMigrationProfilePathV3, &e.profile, 0, 0600, 16384},
		{activationConfigDirV1 + "/grouped-account-preparation.json", &e.accountReceipt, 0, 0600, 16384},
		{DataDir + "/accounts.json", &e.classicAccounts, ids.APIGID, 0440, 16384},
		{routedAccountsPathV3, &e.accounts, ids.APIGID, 0440, 16384},
		{routedNodeLinksPathV3, &e.links, 0, 0600, 4096},
	} {
		*file.data, err = readOwned(file.path, 0, file.group, file.mode, file.size)
		if err != nil {
			return activationEvidenceV1{}, err
		}
	}
	return e, nil
}

func sameActivationEvidenceV1(a, b activationEvidenceV1) bool {
	return bytes.Equal(a.draft, b.draft) && bytes.Equal(a.authorization, b.authorization) && bytes.Equal(a.prepared, b.prepared) &&
		bytes.Equal(a.profile, b.profile) && bytes.Equal(a.accountReceipt, b.accountReceipt) && bytes.Equal(a.classicAccounts, b.classicAccounts) &&
		bytes.Equal(a.accounts, b.accounts) && bytes.Equal(a.links, b.links)
}

func excludeActivationWritersV1(ctx context.Context) error {
	if err := activationUnitsDrainedV1(ctx, []string{activationClassicAPIV1, activationClassicSocketV1}, false); err != nil {
		return err
	}
	if err := activationUnitsDrainedV1(ctx, activationGroupedUnitsV1, false); err != nil {
		return err
	}
	for _, units := range [][]string{activationClassicUnitsV1, activationGroupedUnitsV1} {
		if _, err := activationSystemctlV1(ctx, "mask", units...); err != nil {
			return err
		}
	}
	if err := syncDirectory("/etc/systemd/system"); err != nil {
		return err
	}
	if err := closeActivationClassicV1(ctx); err != nil {
		return err
	}
	if _, err := activationSystemctlV1(ctx, "stop", activationClassicUnitsV1...); err != nil {
		return err
	}
	return ensureActivationExclusionV1(ctx)
}

func ensureActivationExclusionV1(ctx context.Context) error {
	for _, units := range [][]string{activationClassicUnitsV1, activationGroupedUnitsV1} {
		if err := activationUnitsDrainedV1(ctx, units, true); err != nil {
			return err
		}
	}
	return activationClassicGoneV1()
}

func checkActivationParentsV1(node routedNodeLinksV3) error {
	for _, binding := range []routedNodeParentV3{node.LAN, node.WAN} {
		current, err := net.InterfaceByName(binding.Name)
		if err != nil || current.Index != binding.Index || current.MTU != binding.MTU ||
			current.HardwareAddr.String() != binding.MAC || current.Flags&net.FlagUp == 0 {
			return ErrIdentity
		}
	}
	return nil
}

func startActivatedRuntimeV1(ctx context.Context, c Config) error {
	ca, err := readOwned(DataDir+"/ca.crt", 0, 0, 0644, 16384)
	trust := x509.NewCertPool()
	if err != nil || !trust.AppendCertsFromPEM(ca) {
		return ErrConfiguration
	}
	if _, err := activationSystemctlV1(ctx, "unmask", activationGroupedUnitsV1...); err != nil {
		return err
	}
	if _, err := activationSystemctlV1(ctx, "start", activationGroupedServiceV1); err != nil {
		return err
	}
	ready, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS13}}
	for {
		if h, err := GroupedHealthV3(ready, c); err == nil && h.Available {
			conn, err := dial.DialContext(ready, "tcp", c.ListenAddress)
			if err == nil {
				return conn.Close()
			}
		}
		state, err := activationSystemctlV1(ready, "show", activationGroupedServiceV1)
		if err != nil || activationUnitDrainedV1(string(state), false) ||
			strings.Contains("\n"+string(state), "\nActiveState=failed\n") {
			return ErrUnavailable
		}
		select {
		case <-ready.Done():
			return ErrUnavailable
		case <-ticker.C:
		}
	}
}
