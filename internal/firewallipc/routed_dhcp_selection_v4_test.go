package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedDHCPSelectionV4IsOnlyCompleteInspectionHint(t *testing.T) {
	for _, mode := range []string{"attach", "check"} {
		for _, state := range []configpoc.IntegrityStateV1{configpoc.IntegrityCompleteV1, configpoc.IntegrityUnavailableV1} {
			p, err := json.Marshal(RoutedIntegrityV3{Mode: mode, Selection: integrityWireRefV3()})
			if err != nil {
				t.Fatal(err)
			}
			request := RoutedRequestV3{RoutedProtocolV3, strings.Repeat("a", 32), 1, 22, "routed", "inspect", p}
			payload, err := json.Marshal(RoutedIntegrityResultV3{Mode: mode, Result: configpoc.IntegrityResultV1{Selection: integrityWireRefV3(), State: state}, DHCPSelected: true})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(RoutedReplyV3{RoutedProtocolV3, request.Run, 1, 22, "routed", "inspect", "", payload})
			if err != nil {
				t.Fatal(err)
			}
			_, result, err := DecodeRoutedReplyV3(raw, request)
			want := mode == "check" && state == configpoc.IntegrityCompleteV1
			if (err == nil) != want || want && !result.DHCPSelected {
				t.Fatalf("%s %s: %v", mode, state, err)
			}
		}
	}
}
