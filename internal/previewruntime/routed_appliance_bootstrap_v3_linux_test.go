//go:build linux

package previewruntime

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedLaunchV3ExplicitStoreBudget(t *testing.T) {
	supervisor := &RoutedLaunchSupervisorV3{}
	old := supervisor.bootstrap(0, 0)
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"store_budget", "management", "integrity"} {
		if bytes.Contains(data, []byte(field)) {
			t.Fatal("default profile gained opt-in field", field)
		}
	}
	supervisor.resources.StoreBudget = configpoc.BudgetV2{Bytes: 123456, Inodes: 987}
	current := supervisor.bootstrap(22, 1)
	if current.StoreBudget == nil || *current.StoreBudget != supervisor.resources.StoreBudget {
		t.Fatal("explicit store budget not bound")
	}
	current.StoreBudget.Bytes++
	if supervisor.resources.StoreBudget.Bytes != 123456 {
		t.Fatal("bootstrap changed retained supervisor budget")
	}
	f := &routedLaunchFilesV3{}
	if got := f.context(old); got.StoreBudget != (configpoc.BudgetV2{}) || got.Management != nil {
		t.Fatal("legacy context invented resources")
	}
}
