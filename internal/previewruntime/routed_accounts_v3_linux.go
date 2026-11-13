//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const routedAccountsPathV3 = routedDeploymentDataV3 + "/accounts.json"

// Account authority remains separate from configuration-reader permissions.
// The old credential file is retained but never used as a grouped fallback.
func routedAccountImageV3(source, draft []byte) ([]byte, error) {
	var accounts []adminauth.Account
	var plan routedMigrationPlanV3
	if len(source) == 0 || len(source) > 16384 || len(draft) == 0 || len(draft) > 65536 || !jsoncheck.UniqueControlFields(source) || !jsoncheck.UniqueControlFields(draft) || firewallipc.Decode(source, &accounts) != nil || firewallipc.Decode(draft, &plan) != nil {
		return nil, ErrConfiguration
	}
	digest := sha256.Sum256(source)
	if validateMigrationPlanV3(plan, accounts, hex.EncodeToString(digest[:]), plan.Firewall) != nil {
		return nil, ErrConfiguration
	}
	for i := range accounts {
		for _, subject := range plan.Subjects {
			if subject.Login == accounts[i].Username {
				accounts[i].SubjectID, accounts[i].CredentialRevision = subject.ID, subject.CredentialRevision
			}
		}
	}
	if _, err := adminauth.New(accounts, func(adminauth.Event) error { return nil }); err != nil {
		return nil, ErrConfiguration
	}
	return marshal(accounts), nil
}

func loadRoutedAccountsV3(ids Identities) ([]adminauth.Account, error) {
	raw, err := readOwned(routedAccountsPathV3, 0, ids.APIGID, 0440, 16384)
	if err != nil {
		return nil, err
	}
	var accounts []adminauth.Account
	if !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &accounts) != nil {
		return nil, ErrConfiguration
	}
	for _, account := range accounts {
		if account.SubjectID == "" || account.CredentialRevision == "" {
			return nil, ErrIdentity
		}
	}
	return accounts, nil
}

// PrepareRoutedAccountsV3 creates a private, inactive credential artifact only.
// It preserves original accounts/roles/digests and binds the new subject fields
// to the exact inspected draft. It grants no readiness or historical ownership.
func PrepareRoutedAccountsV3(ctx context.Context, c Config) (string, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return "", ErrIdentity
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		return "", err
	}
	profile, err := readOwned(routedMigrationProfilePathV3, 0, 0, 0600, 16384)
	if err != nil {
		return "", err
	}
	var converted routedMigrationProfileResultV3
	if !jsoncheck.UniqueControlFields(profile) || firewallipc.Decode(profile, &converted) != nil || converted.Version != 1 {
		return "", ErrConfiguration
	}
	prepared, err := readOwned(migrationPreparedPathV3, 0, 0, 0600, 16384)
	if err != nil {
		return "", err
	}
	var preparation routedMigrationPreparedV3
	preparedDigest := sha256.Sum256(prepared)
	if converted.PreparedSHA256 != hex.EncodeToString(preparedDigest[:]) || !jsoncheck.UniqueControlFields(prepared) || firewallipc.Decode(prepared, &preparation) != nil || validateMigrationPreparedV3(preparation, converted.PlanSHA256) != nil {
		return "", ErrConfiguration
	}
	seen := map[[2]uint64]bool{}
	reader := converted.Access[0].ReaderGID
	for _, access := range converted.Access {
		key := [2]uint64{access.Device, access.Inode}
		if access.Version != 1 || access.OwnerUID != ids.APIUID || access.ReaderGID != reader || reader == 0 || reader == ids.APIGID || reader == ids.IPCGID || access.Inode == 0 || seen[key] {
			return "", ErrIdentity
		}
		seen[key] = true
	}
	inspected, err := InspectRoutedMigrationV3(ctx, c)
	if err != nil || inspected.PlanSHA256 != converted.PlanSHA256 {
		return "", ErrConfiguration
	}
	draft, err := readOwned(routedMigrationPlanPathV3, 0, 0, 0600, 65536)
	if err != nil {
		return "", err
	}
	source, err := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if err != nil {
		return "", err
	}
	image, err := routedAccountImageV3(source, draft)
	if err != nil {
		return "", err
	}
	if ownedDirectory(routedDeploymentDataV3, 0, 0, 0755) != nil {
		return "", ErrIdentity
	}
	root, err := os.OpenRoot(routedDeploymentDataV3)
	if err != nil {
		return "", err
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if !fenceNoACLV3(parent, true) {
		return "", ErrIdentity
	}
	if err = writeNew(root, "accounts.json", image, 0440, 0, ids.APIGID); err != nil {
		return "", err
	}
	if err = parent.Sync(); err != nil {
		return "", err
	}
	after, err := InspectRoutedMigrationV3(ctx, c)
	if err != nil || after.PlanSHA256 != inspected.PlanSHA256 || after.Firewall != inspected.Firewall {
		return "", ErrIdentity
	}
	digest := sha256.Sum256(image)
	profileDigest, sourceDigest := sha256.Sum256(profile), sha256.Sum256(source)
	receipt := struct {
		Version        int       `json:"version"`
		Actor          string    `json:"actor"`
		CreatedAt      time.Time `json:"created_at"`
		PlanSHA256     string    `json:"plan_sha256"`
		ProfileSHA256  string    `json:"profile_sha256"`
		SourceSHA256   string    `json:"source_sha256"`
		AccountsSHA256 string    `json:"accounts_sha256"`
	}{1, "local-root", time.Now().UTC(), inspected.PlanSHA256, hex.EncodeToString(profileDigest[:]), hex.EncodeToString(sourceDigest[:]), hex.EncodeToString(digest[:])}
	operational, err := os.OpenRoot("/etc/andeiva-preview")
	if err != nil {
		return "", err
	}
	defer operational.Close()
	if err = writeNew(operational, "grouped-account-preparation.json", marshal(receipt), 0600, 0, 0); err != nil {
		return "", err
	}
	if err = syncDirectory(operational.Name()); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}
