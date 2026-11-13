//go:build linux

package previewruntime

import (
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestRoutedRetirementBootstrapV3SeparatesHelperAndAPI(t *testing.T) {
	binding := RoutedFreshScopeBindingV3{ReceiptSHA256: strings.Repeat("b", 64), NewIdentity: networkexecutor.OwnedNamespaceIdentity{UID: 62002, GID: 62003, Namespace: 42, Host: 40, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}}
	supervisor := &RoutedLaunchSupervisorV3{resources: RoutedLaunchResourcesV3{FreshScope: &RoutedFreshScopeOptionsV3{Binding: binding}}}
	helper := supervisor.bootstrap(0, 0)
	api := supervisor.bootstrap(123, 1)
	if !helper.FreshScope || helper.FreshScopeBinding == nil || *helper.FreshScopeBinding != binding || !api.FreshScope || api.FreshScopeBinding != nil {
		t.Fatal("API bootstrap received helper-only receipt authority")
	}
	helper.FreshScopeBinding.ReceiptSHA256 = strings.Repeat("c", 64)
	if supervisor.resources.FreshScope.Binding != binding {
		t.Fatal("child bootstrap aliases supervisor authority")
	}
	apiContext := (&routedLaunchFilesV3{}).context(api)
	if !apiContext.FreshScopeEnabled || apiContext.FreshScope != nil {
		t.Fatal("API context contains helper receipt")
	}
	legacy := (&RoutedLaunchSupervisorV3{}).bootstrap(123, 1)
	if legacy.FreshScope || legacy.FreshScopeBinding != nil {
		t.Fatal("capability enabled without root receipt")
	}
}
