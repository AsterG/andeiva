//go:build linux

package previewruntime

import (
	"encoding/json"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"strings"
	"testing"
)

func TestRoutedRetirementBootstrapV4KeepsAuthorityHelperOnly(t *testing.T) {
	binding := RoutedRebootScopeBindingV4{ReceiptSHA256: strings.Repeat("b", 64), NewIdentity: networkexecutor.OwnedNamespaceIdentity{UID: 62002, GID: 62003, Namespace: 42, Host: 40, BootID: "22345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}}
	supervisor := &RoutedLaunchSupervisorV3{resources: RoutedLaunchResourcesV3{RebootScope: &RoutedRebootScopeOptionsV4{Binding: binding}}}
	helper, api := supervisor.bootstrap(0, 0), supervisor.bootstrap(123, 1)
	helper.Integrity, api.Integrity = true, true // Directory inheritance is qualified separately.
	if !validRoutedScopeBootstrapV4(helper, RoutedHelperRoleV3) || !validRoutedScopeBootstrapV4(api, RoutedAPIRoleV3) {
		t.Fatal("valid reboot profile refused")
	}
	if helper.FreshScope || api.FreshScope || !helper.RebootScope || !api.RebootScope || helper.RebootScopeBinding == nil || *helper.RebootScopeBinding != binding || api.RebootScopeBinding != nil {
		t.Fatal("reboot authority leaked or profiles mixed")
	}
	raw, err := json.Marshal(api)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), binding.ReceiptSHA256) || strings.Contains(string(raw), "scope_binding") {
		t.Fatal("API wire contains root binding")
	}
	helper.RebootScopeBinding.ReceiptSHA256 = strings.Repeat("c", 64)
	if supervisor.resources.RebootScope.Binding != binding {
		t.Fatal("bootstrap aliases root binding")
	}
	c := (&routedLaunchFilesV3{}).context(api)
	if !c.RebootScopeEnabled || c.FreshScopeEnabled || c.RebootScope != nil || c.FreshScope != nil {
		t.Fatal("API received receipt")
	}
}

func TestRoutedRetirementBootstrapV4RejectsAmbiguousAuthority(t *testing.T) {
	fresh := &RoutedFreshScopeBindingV3{}
	reboot := &RoutedRebootScopeBindingV4{}
	for name, b := range map[string]routedLaunchBootstrapV3{
		"both":                           {Integrity: true, FreshScope: true, RebootScope: true, FreshScopeBinding: fresh, RebootScopeBinding: reboot},
		"fresh_binding_without_feature":  {Integrity: true, FreshScopeBinding: fresh},
		"reboot_binding_without_feature": {Integrity: true, RebootScopeBinding: reboot},
		"fresh_without_integrity":        {FreshScope: true, FreshScopeBinding: fresh},
		"reboot_without_integrity":       {RebootScope: true, RebootScopeBinding: reboot},
		"crossed_binding":                {Integrity: true, FreshScope: true, RebootScopeBinding: reboot},
	} {
		t.Run(name, func(t *testing.T) {
			for _, role := range []string{RoutedHelperRoleV3, RoutedAPIRoleV3} {
				if validRoutedScopeBootstrapV4(b, role) {
					t.Fatal("invalid authority accepted", role)
				}
			}
		})
	}
	for _, b := range []routedLaunchBootstrapV3{{Integrity: true, FreshScope: true}, {Integrity: true, RebootScope: true}} {
		if validRoutedScopeBootstrapV4(b, RoutedHelperRoleV3) || !validRoutedScopeBootstrapV4(b, RoutedAPIRoleV3) {
			t.Fatal("missing helper binding or API feature rejected incorrectly")
		}
	}
	for _, b := range []routedLaunchBootstrapV3{{Integrity: true, FreshScope: true, FreshScopeBinding: fresh}, {Integrity: true, RebootScope: true, RebootScopeBinding: reboot}} {
		if validRoutedScopeBootstrapV4(b, RoutedAPIRoleV3) || validateRoutedScopeReceiptV4(nil, b) == nil {
			t.Fatal("API binding or missing receipt accepted")
		}
	}
}
