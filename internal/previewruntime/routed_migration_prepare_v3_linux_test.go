//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

type prepareMigrationReadbackFixtureV3 struct {
	t           *testing.T
	roots       [6]*os.Root
	fw          string
	calls, fail int
}

func (v *prepareMigrationReadbackFixtureV3) VerifyMigratedSources(ctx context.Context, fp [2]configpoc.LegacyFingerprintV2, fw, local configpoc.Revision) error {
	v.calls++
	if ctx.Err() != nil || fp[0].Domain != "firewall" || fw.Hash != v.fw || len(fw.Config.Rules) != 2 || local.Config.SchemaVersion != 3 || len(local.Config.LocalServices.Services) != 0 {
		return errors.New("invalid proxy correlation")
	}
	if _, err := configpoc.InspectLegacyV2(v.roots[0], "firewall"); !errors.Is(err, configpoc.ErrLocked) {
		return errors.New("FW source lock released before callback")
	}
	if v.calls == 5 {
		if fp[1].Source == "" {
			return errors.New("missing selected local source")
		}
		if _, err := configpoc.InspectLegacyV2(v.roots[1], "local_services"); !errors.Is(err, configpoc.ErrLocked) {
			return errors.New("local source lock released before publication")
		}
	}
	if v.calls == v.fail {
		return errors.New("modeled readback failure")
	}
	return nil
}
func migrationPreparationFixtureV3(t *testing.T) ([6]*os.Root, routedMigrationPlanV3, routedMigrationAuthorizationV3, []adminauth.Account, string, *prepareMigrationReadbackFixtureV3) {
	t.Helper()
	var roots [6]*os.Root
	base := t.TempDir()
	for i := range roots {
		path := filepath.Join(base, string(rune('a'+i)))
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		roots[i] = root
		t.Cleanup(func() { _ = root.Close() })
	}
	enabled, disabled := true, false
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{
		{ID: "tcp-original", Action: "allow", Enabled: &enabled, Match: &configpoc.Match{Source: "198.18.0.1/32", Destination: "198.18.0.2/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 443, To: 443}}},
		{ID: "udp-retained", Action: "allow", Enabled: &disabled, Match: &configpoc.Match{Source: "198.18.0.1/32", Destination: "198.18.0.2/32", Protocol: "udp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 53, To: 53}}}}}
	// Modeled engine only creates a valid historical FW fixture. No real kernel claim.
	source, err := configpoc.Open(roots[0].Name(), []configpoc.Engine{configpoc.NewSimEngine("prepare-fixture-only")}, configpoc.Options{Initial: &config})
	if err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	fp, err := configpoc.InspectLegacyV2(roots[0], "firewall")
	if err != nil {
		t.Fatal(err)
	}
	credential := sha256.Sum256([]byte("modeled-test-not-live"))
	accounts := []adminauth.Account{{Username: "admin-a", Role: "admin", CredentialSHA256: hex.EncodeToString(credential[:])}}
	raw := marshal(accounts)
	accountHash := sha256.Sum256(raw)
	digest := hex.EncodeToString(accountHash[:])
	p, err := inspectMigrationPlanV3(accounts, digest, fp)
	if err != nil {
		t.Fatal(err)
	}
	draft := marshal(p)
	hash := sha256.Sum256(draft)
	a := routedMigrationAuthorizationV3{Version: 1, PlanSHA256: hex.EncodeToString(hash[:]), Bindings: []configpoc.LegacyBindingV2{}}
	revision, err := configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	return roots, p, a, accounts, digest, &prepareMigrationReadbackFixtureV3{t: t, roots: roots, fw: revision.Hash}
}
func TestRoutedMigrationPrepareV3PreservesFWAndCreatesOneLocalSource(t *testing.T) {
	roots, p, a, accounts, digest, verify := migrationPreparationFixtureV3(t)
	out, err := prepareMigrationRootsV3(context.Background(), roots, p, a, accounts, digest, verify, configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 32768})
	if err != nil || validateMigrationPreparedV3(out, a.PlanSHA256) != nil || out.Version != 1 || verify.calls != 5 || out.LocalOrigin.Source.Sequence != 1 || out.LocalOrigin.Source.Projection != 1 || out.PlanSHA256 != a.PlanSHA256 {
		t.Fatal(out, err, verify.calls)
	}
	if actual, e := configpoc.InspectLegacyV2(roots[0], "firewall"); e != nil || actual != p.Firewall {
		t.Fatal("FW history changed", actual, e)
	}
	if accounts[0].SubjectID != "" {
		t.Fatal("account source changed")
	}
	if info, e := roots[2].Stat("selected.json"); e != nil || info.Size() == 0 {
		t.Fatal("no durable selected migration", e)
	}
	if _, err = prepareMigrationRootsV3(context.Background(), roots, p, a, accounts, digest, verify, configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 32768}); err == nil {
		t.Fatal("existing prepared roots reused")
	}
}
func TestRoutedMigrationPrepareV3ReadbackFailurePreservesSources(t *testing.T) {
	for _, at := range []int{1, 2, 3, 4, 5} {
		t.Run(string(rune('0'+at)), func(t *testing.T) {
			roots, p, a, accounts, digest, verify := migrationPreparationFixtureV3(t)
			verify.fail = at
			out, err := prepareMigrationRootsV3(context.Background(), roots, p, a, accounts, digest, verify, configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 32768})
			if err == nil || out.Version != 0 {
				t.Fatal("failed proof acknowledged", out, err)
			}
			if actual, e := configpoc.InspectLegacyV2(roots[0], "firewall"); e != nil || actual != p.Firewall {
				t.Fatal("original history changed", actual, e)
			}
		})
	}
}
func TestRoutedMigrationPrepareV3AuthorizationExactDraftAndSubject(t *testing.T) {
	_, p, a, _, _, _ := migrationPreparationFixtureV3(t)
	draft := marshal(p)
	if _, _, err := decodeMigrationAuthorizationV3(marshal(a), draft); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*routedMigrationAuthorizationV3){
		func(a *routedMigrationAuthorizationV3) { a.PlanSHA256 = "" },
		func(a *routedMigrationAuthorizationV3) {
			a.Bindings = []configpoc.LegacyBindingV2{{Source: p.Firewall.Source, Actor: "admin-a", Subject: "foreign", ReceiptIndex: p.Firewall.ReceiptIndex}}
		},
		func(a *routedMigrationAuthorizationV3) {
			a.Bindings = []configpoc.LegacyBindingV2{{Source: p.Firewall.Source, Actor: "admin-a", Subject: p.Subjects[0].ID, ReceiptIndex: "foreign"}}
		},
	} {
		var changed routedMigrationAuthorizationV3
		if json.Unmarshal(marshal(a), &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		if _, _, err := decodeMigrationAuthorizationV3(marshal(changed), draft); err == nil {
			t.Fatal("unauthorized binding accepted")
		}
	}
	if RunRoutedMigrationPrepareRoleV3(nil) == nil {
		t.Fatal("nil role context")
	}
}

func TestRoutedMigrationPrepareV3PipeCorrelationAndBounds(t *testing.T) {
	session := strings.Repeat("a", 64)
	valid := migrationPrepareFrameV3{Version: 1, Sequence: 1, Kind: "verify", Request: session}
	if _, err := decodeMigrationPrepareFrameV3(marshal(valid), 1, session); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*migrationPrepareFrameV3){
		func(f *migrationPrepareFrameV3) { f.Version = 2 }, func(f *migrationPrepareFrameV3) { f.Sequence = 2 }, func(f *migrationPrepareFrameV3) { f.Request = strings.Repeat("b", 64) }, func(f *migrationPrepareFrameV3) { f.Kind = "apply" }, func(f *migrationPrepareFrameV3) { f.Kind = "prepared"; f.Prepared = &routedMigrationPreparedV3{} }, func(f *migrationPrepareFrameV3) { f.Prepared = &routedMigrationPreparedV3{} },
	} {
		f := valid
		mutate(&f)
		if _, err := decodeMigrationPrepareFrameV3(marshal(f), 1, session); err == nil {
			t.Fatal("foreign/early/effect frame accepted")
		}
	}
	if _, err := decodeMigrationPrepareFrameV3([]byte(strings.Repeat(" ", migrationPrepareFrameLimitV3)), 1, session); err == nil {
		t.Fatal("oversize accepted")
	}
	request := []byte("exact request\n")
	hash := sha256.Sum256(request)
	ack := migrationPrepareAckV3{Version: 1, Sequence: 1, Request: hex.EncodeToString(hash[:])}
	if validateMigrationPrepareAckV3(marshal(ack), 1, request) != nil {
		t.Fatal("valid correlation refused")
	}
	if validateMigrationPrepareAckV3(marshal(ack), 2, request) == nil || validateMigrationPrepareAckV3(marshal(ack), 1, []byte("changed")) == nil || validateMigrationPrepareAckV3([]byte(`{"version":1,"version":1}`), 1, request) == nil {
		t.Fatal("replayed/foreign/ambiguous ACK accepted")
	}
}
