//go:build linux

package configpoc

import (
	"context"
	"reflect"
	"testing"
)

// Only physical replies are doubled; all revision, commit/confirm and selected
// history changes below use the actual coordinator and store.
type serviceRestartNoNetworkFixtureV3 struct{ *boundaryAuthorityFixtureV2 }

func (a *serviceRestartNoNetworkFixtureV3) Prepare(ctx context.Context, target RoutedActivationBundleV1, baseline *RoutedBaselineV1) (RoutedPreparationV1, error) {
	if target.Firewall.Config.SchemaVersion != 4 {
		return a.boundaryAuthorityFixtureV2.Prepare(ctx, target, baseline)
	}
	p, err := a.PrepareBoot(ctx, target, target)
	if err != nil {
		return p, err
	}
	p.Before.LegacyFirewall = TableStateV1{Presence: Present, Revision: &a.legacy}
	return p, nil
}
func (a *serviceRestartNoNetworkFixtureV3) Apply(ctx context.Context, p RoutedSelectedPlanV1) error {
	if err := a.boundaryAuthorityFixtureV2.Apply(ctx, p); err != nil {
		return err
	}
	if p.target.Firewall.Config.SchemaVersion == 4 {
		a.legacy = p.target.Firewall
	}
	return nil
}

func TestRoutedFreshScopeV3ServiceRestartKeepsRunningDenyAndStartupAllow(t *testing.T) {
	c, old, principal, _ := boundaryCoordinatorFixtureV2(t)
	m := c.store.reserves
	c.store = sharedTestStoreV2(t, c.store)
	c.store.reserves, c.options.SharedReader = m, c.store.access
	c.options.Routed = &serviceRestartNoNetworkFixtureV3{old}
	boot := v2BootID(old.identity.BootID)
	c.options.BootID = &boot
	if err := c.bootStartupLocked(context.Background(), boot); err != nil {
		t.Fatal(err)
	}
	startup := c.store.state.Configuration.Firewall.Startup
	if len(startup.Config.Rules) == 0 || startup.Config.Rules[0].Action != "allow" {
		t.Fatal("startup fixture must allow")
	}
	deny := Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}}
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &deny}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	op, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: op.ID, Target: result.Current.Running.Hash}); err != nil {
		t.Fatal(err)
	}
	before := clone(*c.store.state.Configuration)
	if before.Firewall.Running.Hash == startup.Hash || len(before.Firewall.Running.Config.Rules) != 0 {
		t.Fatal("running must deny")
	}
	fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
	opened, err := reopenFreshScopeFixtureV3(t, c, fresh, proof)
	if err != nil {
		t.Fatal(err)
	}
	after := opened.store.state.Configuration
	if after.Running.Hash != before.Running.Hash || !reflect.DeepEqual(after.Firewall.Startup, before.Firewall.Startup) || !reflect.DeepEqual(after.Firewall.LastGood, before.Firewall.LastGood) || !reflect.DeepEqual(after.LocalServices, before.LocalServices) || fresh.current != before.Running.Hash {
		t.Fatal("service restart changed effective or saved policy")
	}
	var record v2RecoveryRecord
	if opened.store.readObject(after.LastCompletedBoot, &record) != nil {
		t.Fatal("missing completed record")
	}
	if record.ServiceRestart == nil {
		t.Fatal("missing typed service restart")
	}
	var source, prior, target v2Configuration
	if opened.store.readObject(record.ServiceRestart.Source, &source) != nil || !reflect.DeepEqual(source, before) || opened.store.readObject(record.Previous, &prior) != nil || opened.store.readObject(record.Target, &target) != nil || !validRecoveryBootTargetV3(record, prior, target, opened.store.readObject) {
		t.Fatal("restart source/target not exact")
	}
	wrong, err := bootTargetV2(prior)
	if err != nil || validRecoveryBootTargetV3(record, prior, wrong, opened.store.readObject) || validBootTargetV2(prior, target) {
		t.Fatal("Startup and service restart targets interchanged")
	}
}
