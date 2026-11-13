package routedactivation

import (
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func noServicesTargetV3(t testing.TB) configpoc.RoutedActivationBundleV1 {
	t.Helper()
	_, _, original := artifactFixture(t)
	policy := *original.Firewall.Config.Routed
	policy.Rules, policy.NAT = nil, nil
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	localConfig := *original.LocalServices.Config.LocalServices
	localConfig.Services = nil
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
	if err != nil {
		t.Fatal(err)
	}
	target, err := configpoc.NewRoutedActivationBundleV1(firewall, local)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// The production grouped engine and compilers run here, but every kernel,
// network and listener observation is modeled; this is not native evidence.
func TestNoServicesV3EngineRejectsIndependentListenerAndTableDriftBeforeEffects(t *testing.T) {
	for _, fault := range []string{"listener", "local-table", "unavailable-table"} {
		t.Run(fault, func(t *testing.T) {
			f, saved := noNetworkBootFixture(t)
			confirmFixture(t, f)
			target := noServicesTargetV3(t)
			if !configpoc.RoutedNoServicesTransitionV3(saved.Firewall, saved.LocalServices, target.Firewall, target.LocalServices) {
				t.Fatal("fixture is outside the metadata exception")
			}
			writes, networkCalls, listenerCalls := len(f.kernel.batches), f.network.calls, f.listeners.calls
			switch fault {
			case "listener":
				f.listeners.actual = []localpolicy.Listener{{Owner: "foreign", Service: "foreign", Interface: "lan0", LocalAddress: "198.18.0.1", Protocol: localpolicy.TCP, Port: 443}}
			case "local-table":
				f.kernel.objects[LocalTable] = []map[string]any{{"table": map[string]any{"name": "foreign"}}}
			case "unavailable-table":
				f.kernel.readFail = true
			}
			if _, err := f.engine.Prepare(context.Background(), target); err == nil {
				t.Fatal("metadata exception bypassed independent observation")
			}
			if len(f.kernel.batches) != writes || f.network.calls != networkCalls || f.listeners.calls != listenerCalls {
				t.Fatal("refused observation caused effects")
			}
		})
	}
}

func TestNoServicesV3EnginePreservesAbsentLocalBaselineOnRollback(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	confirmFixture(t, f)
	target := noServicesTargetV3(t)
	if !configpoc.RoutedNoServicesTransitionV3(saved.Firewall, saved.LocalServices, target.Firewall, target.LocalServices) || len(saved.LocalServices.Config.LocalServices.Interfaces) != 0 {
		t.Fatal("expected original empty local revision")
	}
	plan, receipt := armFixtureOperation(t, f, "no-services", saved, target)
	if err := f.group.ConfirmLease(context.Background(), plan, receipt); err != nil {
		t.Fatal(err)
	}
	if len(f.listeners.actual) != 0 || !f.network.active || f.engine.Current() != target.Composite.Hash {
		t.Fatal("modeled target differs or acquired a listener")
	}
	plan, receipt = armFixtureOperation(t, f, "original-empty-local", target, saved)
	if err := f.group.ConfirmLease(context.Background(), plan, receipt); err != nil {
		t.Fatal(err)
	}
	_, present := f.kernel.objects[LocalTable]
	if f.engine.Current() != saved.Composite.Hash || present || f.network.active || len(f.listeners.actual) != 0 {
		t.Fatal("rollback invented a local table/listener or lost original bundle")
	}
}
