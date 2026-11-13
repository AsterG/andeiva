package routedactivation

import "github.com/AsterG/andeiva/internal/networkexecutor"
import "github.com/AsterG/andeiva/internal/networkplan"

func networkArtifactProfileV3(r networkplan.Revision) (int, string) {
	if _, err := networkexecutor.CanonicalLANBootstrapPlanV3(r); err == nil {
		return 3, "dhcp-lan"
	}
	return 1, ""
}
