package adminapi

import (
	"encoding/json"
	"testing"
)

func TestFirewallRuleStateCapabilityAndAdmission(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := fixtureServer(t, "admin")
		f.server.Config.Handler.(*handler).options.FirewallRuleState = enabled
		_, token, _ := f.login(t, "cli")
		headers := map[string]string{"Authorization": "Bearer " + token, "X-ANDEIVA-Client": "cli", "Content-Type": "application/json"}
		code, body, _ := f.request(t, "GET", "/api/v1/capabilities", "", headers)
		var caps Capabilities
		if code != 200 || json.Unmarshal([]byte(body), &caps) != nil || caps.FirewallRuleEnabled != enabled || len(caps.FirewallConfigSchemaVersions) != 1+btoi(enabled) {
			t.Fatal("capability does not reflect runtime", code)
		}
		request := `{"operation":"stage","key":"state-capability","expected_generation":1,"config":{"schema_version":4,"default_action":"deny","rules":[]}}`
		code, _, _ = f.request(t, "POST", "/api/v1/firewall/transactions", request, headers)
		if enabled {
			if code != 200 || f.backend.calls != 1 {
				t.Fatal("enabled runtime did not admit typed schema", code)
			}
		} else if code != 400 || f.backend.calls != 0 {
			t.Fatal("unsupported schema reached backend", code)
		}
	}
}
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}
