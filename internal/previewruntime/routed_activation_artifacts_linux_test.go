//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func activationArtifactsFixtureV1(t *testing.T) (activationEvidenceV1, Identities, routedReadBudgetV3) {
	t.Helper()
	roots, plan, auth, accounts, digest, verify := migrationPreparationFixtureV3(t)
	prepared, err := prepareMigrationRootsV3(context.Background(), roots, plan, auth, accounts, digest, verify, configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	ids := Identities{SchemaVersion: 1, APIUID: 101, APIGID: 103, HelperUID: 102, IPCGID: 105}
	e := activationEvidenceV1{draft: marshal(plan), authorization: marshal(auth), classicAccounts: marshal(accounts), prepared: marshal(prepared)}
	e.accounts, err = routedAccountImageV3(e.classicAccounts, e.draft)
	if err != nil {
		t.Fatal(err)
	}
	profile := routedMigrationProfileResultV3{
		Version: 1, PlanSHA256: auth.PlanSHA256, PreparedSHA256: retirementDigestV3(e.prepared),
	}
	for i := range profile.Access {
		profile.Access[i] = routedAccessRecordV3{Version: 1, OwnerUID: ids.APIUID, ReaderGID: 110, Device: 2, Inode: uint64(i + 1)}
	}
	e.profile = marshal(profile)
	e.accountReceipt = marshal(routedAccountPreparationV3{
		Version: 1, Actor: "local-root", CreatedAt: time.Now().UTC(), PlanSHA256: auth.PlanSHA256,
		ProfileSHA256: retirementDigestV3(e.profile), SourceSHA256: digest,
		AccountsSHA256: retirementDigestV3(e.accounts),
	})
	e.links = marshal(routedNodeLinksV3{
		Version: 1, Identity: strings.Repeat("a", 32),
		LAN: routedNodeParentV3{Index: 2, Name: "ens34", MAC: "02:00:00:00:00:03", MTU: 1500},
		WAN: routedNodeParentV3{Index: 3, Name: "ens33", MAC: "02:00:00:00:00:04", MTU: 1500},
	})
	budget := routedReadBudgetV3{Entries: 200, Objects: 160, Edges: 2000, IOCalls: 20000, Bytes: 1 << 20, ActiveBytes: 1 << 19, Depth: 16}
	return e, ids, budget
}

func TestActivationArtifactsBindPreparedEvidence(t *testing.T) {
	e, ids, budget := activationArtifactsFixtureV1(t)
	out, err := buildActivationArtifactsV1(e, ids, budget)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeRoutedDeploymentV3(out.deployment, ids)
	if err != nil || manifest.ReadBudget != budget || manifest.WriteBudget.Bytes != 1<<30 || len(out.expected.Subjects) != 1 {
		t.Fatal("manifest did not retain preparation limits and subjects", err)
	}
	if err = verifyRoutedCutoverV3(out.cutover, out.deployment, e.links); err != nil {
		t.Fatal("reader rejected cutover", err)
	}
	otherLinks := append(append([]byte{}, e.links...), '\n')
	if err = verifyRoutedCutoverV3(out.cutover, out.deployment, otherLinks); !errors.Is(err, ErrIdentity) {
		t.Fatal("cutover accepted different links", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*activationEvidenceV1)
	}{
		{"stale draft", func(e *activationEvidenceV1) { e.draft = append(append([]byte{}, e.draft...), '\n') }},
		{"stale prepared receipt", func(e *activationEvidenceV1) { e.prepared = append(append([]byte{}, e.prepared...), '\n') }},
		{"changed account role", func(e *activationEvidenceV1) {
			e.accounts = bytes.Replace(e.accounts, []byte(`"role":"admin"`), []byte(`"role":"viewer"`), 1)
		}},
		{"stale account receipt", func(e *activationEvidenceV1) {
			e.accountReceipt = bytes.Replace(e.accountReceipt, []byte(retirementDigestV3(e.profile)), []byte(strings.Repeat("b", 64)), 1)
		}},
		{"extra access pin", func(e *activationEvidenceV1) {
			previous := retirementDigestV3(e.profile)
			e.profile = bytes.Replace(e.profile, []byte("]}"), []byte(",{}]}"), 1)
			e.accountReceipt = bytes.Replace(e.accountReceipt, []byte(previous), []byte(retirementDigestV3(e.profile)), 1)
		}},
		{"unknown deployment evidence", func(e *activationEvidenceV1) { e.links = []byte(`{"version":2}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := e
			tc.mutate(&candidate)
			out, err := buildActivationArtifactsV1(candidate, ids, budget)
			if err == nil || out.deployment != nil || out.cutover != nil {
				t.Fatalf("altered evidence yielded publication bytes: %v", err)
			}
		})
	}
}

func TestPublishActivationRecordNeverReplaces(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test uses a root-owned installation directory")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	if err = area.WriteFile(".grouped.json.pending", []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = publishActivationRecordV1(area, "grouped.json", []byte("replacement")); !errors.Is(err, ErrStorage) {
		t.Fatal("accepted pre-existing staging file", err)
	}
	if _, err = area.Lstat("grouped.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial staging published a final file", err)
	}
	if got, err := area.ReadFile(".grouped.json.pending"); err != nil || string(got) != "interrupted" {
		t.Fatal("lost staging evidence", err)
	}
	if err := area.Symlink("absent", "grouped.json"); err != nil {
		t.Fatal(err)
	}
	if err := publishActivationRecordV1(area, "grouped.json", []byte("replacement")); !errors.Is(err, ErrStorage) {
		t.Fatal("replaced existing dangling symlink", err)
	}
	if got, err := area.Readlink("grouped.json"); err != nil || got != "absent" {
		t.Fatal("lost final-path evidence", err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- publishActivationRecordV1(area, "grouped-cutover.json", []byte("one complete record"))
		}()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) || (first != nil && !errors.Is(first, ErrStorage)) || (second != nil && !errors.Is(second, ErrStorage)) {
		t.Fatalf("concurrent publication: %v, %v", first, second)
	}
	if got, err := area.ReadFile("grouped-cutover.json"); err != nil || string(got) != "one complete record" {
		t.Fatal("published data incomplete", err)
	}
	if file, err := area.Lstat("grouped-cutover.json"); err != nil || file.Mode().Perm() != 0600 {
		t.Fatal("published data has incorrect permissions", err)
	}
}
