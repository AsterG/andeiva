//go:build linux

package previewruntime

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

type activationEvidenceV1 struct {
	draft, authorization, prepared, profile, accountReceipt, classicAccounts, accounts, links []byte
}

type activationArtifactsV1 struct {
	expected   configpoc.PreparedActivationExpectationV1
	deployment []byte
	cutover    []byte
}

// buildActivationArtifactsV1 binds only the inputs for publication. The future
// installer must hold both writer barriers and run full prepared-state readback
// before publishing the cutover bytes.
func buildActivationArtifactsV1(e activationEvidenceV1, ids Identities, budget routedReadBudgetV3) (activationArtifactsV1, error) {
	plan, grant, err := decodeMigrationAuthorizationV3(e.authorization, e.draft)
	if err != nil {
		return activationArtifactsV1{}, err
	}
	image, err := routedAccountImageV3(e.classicAccounts, e.draft)
	if err != nil || !bytes.Equal(image, e.accounts) {
		return activationArtifactsV1{}, ErrConfiguration
	}
	var prepared routedMigrationPreparedV3
	var profile routedMigrationProfileResultV3
	var receipt routedAccountPreparationV3
	if !decodeActivationEvidenceV1(e.prepared, &prepared) || validateMigrationPreparedV3(prepared, grant.PlanSHA256) != nil ||
		!decodeActivationEvidenceV1(e.profile, &profile) || profile.Version != 1 ||
		profile.PlanSHA256 != grant.PlanSHA256 || profile.PreparedSHA256 != retirementDigestV3(e.prepared) ||
		!decodeActivationEvidenceV1(e.accountReceipt, &receipt) || receipt.Version != 1 || receipt.Actor != "local-root" ||
		receipt.CreatedAt.IsZero() || receipt.PlanSHA256 != grant.PlanSHA256 ||
		receipt.ProfileSHA256 != retirementDigestV3(e.profile) || receipt.SourceSHA256 != plan.AccountsSHA256 ||
		receipt.AccountsSHA256 != retirementDigestV3(e.accounts) {
		return activationArtifactsV1{}, ErrConfiguration
	}
	if _, err := decodeRoutedNodeLinksV3(e.links); err != nil {
		return activationArtifactsV1{}, err
	}
	deployment := marshal(routedDeploymentRecordV3{
		Version: 1, NamespaceProfile: "host-gateway-v2", Identities: ids, AccountsSHA256: receipt.AccountsSHA256,
		LocalOrigin: &prepared.LocalOrigin, Access: profile.Access[:], Profiles: prepared.Profiles[:],
		WriteBudget: prepared.WriteBudget, ReadBudget: budget,
	})
	if _, err := decodeRoutedDeploymentV3(deployment, ids); err != nil {
		return activationArtifactsV1{}, err
	}
	cutover := marshal(routedCutoverRecordV3{
		Version: 1, DeploymentSHA256: retirementDigestV3(deployment), LinksSHA256: retirementDigestV3(e.links),
	})
	return activationArtifactsV1{
		expected: configpoc.PreparedActivationExpectationV1{
			Firewall: plan.Firewall, LocalServices: prepared.LocalOrigin.Source, Subjects: plan.Subjects, Bindings: grant.Bindings,
		},
		deployment: deployment, cutover: cutover,
	}, nil
}

func decodeActivationEvidenceV1(raw []byte, value any) bool {
	// These are product-generated records. Canonical bytes also reject extra
	// elements that decoding into fixed-size arrays would otherwise discard.
	return len(raw) > 0 && len(raw) <= 16384 && jsoncheck.UniqueControlFields(raw) &&
		firewallipc.Decode(raw, value) == nil && bytes.Equal(bytes.TrimSpace(raw), bytes.TrimSpace(marshal(value)))
}

// publishActivationRecordV1 supports only the two installer artifacts. Private
// staging stays in the same directory. A failed publication preserves evidence,
// including a potentially durable final record after a lost sync acknowledgement.
func publishActivationRecordV1(area *os.Root, name string, data []byte) error {
	return publishActivationRecordCheckedV1(area, name, data, nil)
}

func publishActivationRecordCheckedV1(area *os.Root, name string, data []byte, beforeRename func() error) error {
	if area == nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		(name != "grouped.json" && name != "grouped-cutover.json") || len(data) == 0 || len(data) > 16384 {
		return ErrIdentity
	}
	dir, err := area.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer dir.Close()
	var stat unix.Stat_t
	fd := int(dir.Fd())
	if unix.Fstat(fd, &stat) != nil || stat.Mode != unix.S_IFDIR|0755 || stat.Uid != 0 || stat.Gid != 0 || !fenceNoACLV3(dir, true) {
		return ErrIdentity
	}
	if _, err := area.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return ErrStorage
	}
	pending := "." + name + ".pending"
	if _, err := area.Lstat(pending); errors.Is(err, os.ErrNotExist) {
		if writeNew(area, pending, data, 0600, 0, 0) != nil {
			return ErrStorage
		}
	} else if err != nil || beforeRename == nil || verifyStagedActivationRecordV1(area, pending, data) != nil {
		return ErrStorage
	}
	if dir.Sync() != nil {
		return ErrStorage
	}
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if unix.Renameat2(fd, pending, fd, name, unix.RENAME_NOREPLACE) != nil || dir.Sync() != nil {
		return ErrStorage
	}
	return nil
}

func verifyStagedActivationRecordV1(area *os.Root, name string, data []byte) error {
	file, err := area.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrStorage
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode != unix.S_IFREG|0600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size != int64(len(data)) || !fenceNoACLV3(file, false) {
		return ErrStorage
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(data)+1)))
	if err != nil || !bytes.Equal(raw, data) || file.Sync() != nil {
		return ErrStorage
	}
	return nil
}
