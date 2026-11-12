package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

type savedLegacyFault struct {
	stage string
	cause error
	calls []string
}

func (f *savedLegacyFault) step(stage string) error {
	f.calls = append(f.calls, stage)
	if f.stage == stage {
		return f.cause
	}
	return nil
}
func (f *savedLegacyFault) Check(context.Context, []byte) error { return f.step("check") }
func (f *savedLegacyFault) Apply(context.Context, []byte) error { return f.step("apply") }
func (f *savedLegacyFault) Observe(_ context.Context, table routedactivation.Table) ([]byte, bool, error) {
	if table != routedactivation.LegacyTable {
		return nil, false, errors.New("wrong table")
	}
	return []byte(`{}`), f.stage != "absent", f.step("observe")
}

func TestSavedLegacyProvisionPreservesStageAndCause(t *testing.T) {
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("controlled kernel rejection")
	for _, stage := range []string{"check", "apply", "observe", "absent", "verify"} {
		t.Run(stage, func(t *testing.T) {
			fake := &savedLegacyFault{stage: stage, cause: cause}
			err := provisionSavedLegacy(context.Background(), fake, legacy)
			if err == nil || !strings.Contains(err.Error(), "saved schema4 "+stage) {
				t.Fatal("lost failing stage", err)
			}
			if stage == "check" || stage == "apply" || stage == "observe" {
				if !errors.Is(err, cause) || fake.calls[len(fake.calls)-1] != stage {
					t.Fatal("lost cause or continued after failure", err, fake.calls)
				}
			}
		})
	}
}

func TestGroupPresenceRequiresSuccessfulCompleteUniqueTableListing(t *testing.T) {
	listing := `{"nftables":[{"metainfo":{"version":"1.1.3","release_name":"fixture","json_schema_version":1}},{"table":{"family":"inet","name":"` + routednft.TableName + `"}}]}`
	if present, err := tablePresent([]byte(listing), routednft.TableName); err != nil || !present {
		t.Fatal("native table listing rejected", present, err)
	}
	if present, err := tablePresent([]byte(`{"nftables":[]}`), routednft.TableName); err != nil || present {
		t.Fatal("successful explicit absence rejected", present, err)
	}
	for _, invalid := range []string{
		"", `{}`, `{"nftables":null}`, `{"nftables":[]} {}`,
		`{"nftables":[],"nftables":[]}`,
		`{"nftables":[{"metainfo":{}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"x","name":"y"}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"` + routednft.TableName + `"}},{"table":{"family":"inet","name":"` + routednft.TableName + `"}}]}`,
		`{"nftables":[{"chain":{"family":"inet"}}]}`,
	} {
		if present, err := tablePresent([]byte(invalid), routednft.TableName); err == nil || present {
			t.Fatal("ambiguous/failing query became absence", invalid)
		}
	}
	if _, err := groupTableName(routedactivation.Table(255)); err == nil {
		t.Fatal("arbitrary table dispatch accepted")
	}
}

func TestGroupEmptyListenerProfileObservesRealEmptySocketTableShape(t *testing.T) {
	header := "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	if !emptySocketTable([]byte(header)) || !emptySocketTable([]byte(header+"\n")) {
		t.Fatal("native empty table shape rejected")
	}
	for _, invalid := range []string{"", "sl inode\n", header + "0: 0100007F:480B 00000000:0000 0A 0 0 0 0 0 1000 0 42\n", strings.Repeat(" ", (64<<10)+1)} {
		if emptySocketTable([]byte(invalid)) {
			t.Fatal("nonempty/truncated listener table accepted")
		}
	}
}

func TestGroupFixtureResolverBindsOriginalRecordAndDeadline(t *testing.T) {
	policy := routednft.LabPolicy()
	fw, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	localConfig := localpolicy.Config{SchemaVersion: 1}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
	if err != nil {
		t.Fatal(err)
	}
	target, err := configpoc.NewRoutedActivationBundleV1(fw, local)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	plan := configpoc.RoutedTransitionV1{Version: 1, Operation: "fixture", Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: strings.Repeat("3", 64), TargetOwned: strings.Repeat("4", 64), Dependencies: strings.Repeat("5", 64)}
	b := &groupLab{selection: groupSelection{plan: plan, target: target, started: started, deadline: started.Add(30 * time.Second), leaseID: "different-lease"}}
	if _, err := b.resolve(context.Background(), plan, nil, target, b.selection.deadline); err != nil {
		t.Fatal(err)
	}
	wrong := plan
	wrong.BeforeOwned = strings.Repeat("f", 64)
	if _, err := b.resolve(context.Background(), wrong, nil, target, b.selection.deadline); err == nil {
		t.Fatal("foreign artifact context accepted")
	}
	if _, err := b.resolve(context.Background(), plan, nil, target, b.selection.deadline.Add(time.Nanosecond)); err == nil {
		t.Fatal("replacement deadline accepted")
	}
	if _, err := b.resolve(context.Background(), plan, &target, target, b.selection.deadline); err == nil {
		t.Fatal("invented effective previous accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.resolve(ctx, plan, nil, target, b.selection.deadline); err == nil {
		t.Fatal("canceled validation accepted")
	}
}
