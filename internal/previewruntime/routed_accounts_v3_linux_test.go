//go:build linux

package previewruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

func TestRoutedAccountsV3PreservesCredentialAndRole(t *testing.T) {
	accounts := []adminauth.Account{{Username: "admin-a", Role: "admin", CredentialSHA256: strings.Repeat("a", 64)}, {Username: "reader", Role: "viewer", CredentialSHA256: strings.Repeat("b", 64)}}
	source, _ := json.Marshal(accounts)
	digest := sha256.Sum256(source)
	fingerprint := configpoc.LegacyFingerprintV2{Domain: "firewall", Source: strings.Repeat("c", 64), Tip: strings.Repeat("d", 64), Sequence: 10, Projection: 10, ReceiptIndex: strings.Repeat("e", 64)}
	plan, err := inspectMigrationPlanV3(accounts, hex.EncodeToString(digest[:]), fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	draft, _ := json.Marshal(plan)
	image, err := routedAccountImageV3(source, draft)
	if err != nil {
		t.Fatal(err)
	}
	var migrated []adminauth.Account
	if firewallipc.Decode(image, &migrated) != nil || len(migrated) != len(accounts) {
		t.Fatal("invalid account image")
	}
	for i, actual := range migrated {
		old := accounts[i]
		if actual.Username != old.Username || actual.Role != old.Role || actual.CredentialSHA256 != old.CredentialSHA256 || actual.SubjectID != plan.Subjects[i].ID || actual.CredentialRevision != plan.Subjects[i].CredentialRevision || old.SubjectID != "" {
			t.Fatal("account authority changed")
		}
	}
	if sha256.Sum256(source) != digest {
		t.Fatal("original source changed")
	}
	for _, change := range []func(*routedMigrationPlanV3){
		func(p *routedMigrationPlanV3) { p.AccountsSHA256 = strings.Repeat("f", 64) },
		func(p *routedMigrationPlanV3) { p.Subjects = p.Subjects[:1] },
		func(p *routedMigrationPlanV3) { p.Subjects[0].Login = "foreign" },
		func(p *routedMigrationPlanV3) { p.Subjects[0].ID = p.Subjects[1].ID },
		func(p *routedMigrationPlanV3) { p.Subjects[0].Retired = true },
	} {
		var modified routedMigrationPlanV3
		if json.Unmarshal(draft, &modified) != nil {
			t.Fatal("fixture")
		}
		change(&modified)
		raw, _ := json.Marshal(modified)
		if _, err = routedAccountImageV3(source, raw); err == nil {
			t.Fatal("invalid continuity accepted")
		}
	}
	changed := append([]adminauth.Account{}, accounts...)
	changed[1].Role = "admin"
	raw, _ := json.Marshal(changed)
	if _, err = routedAccountImageV3(raw, draft); err == nil {
		t.Fatal("source role escalation accepted")
	}
	changed[1] = accounts[1]
	changed[1].CredentialSHA256 = strings.Repeat("f", 64)
	raw, _ = json.Marshal(changed)
	if _, err = routedAccountImageV3(raw, draft); err == nil {
		t.Fatal("source credential replacement accepted")
	}
}
