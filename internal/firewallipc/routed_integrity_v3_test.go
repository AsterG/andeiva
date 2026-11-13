package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func integrityWireRefV3() configpoc.SelectionReferenceV2 {
	return configpoc.SelectionReferenceV2{Selection: strings.Repeat("1", 64), Previous: strings.Repeat("2", 64), State: strings.Repeat("3", 64), Lineage: "lineage", Sequence: 7, Generation: 6, Mode: "prepare"}
}
func TestRoutedIntegrityV3WireStrictness(t *testing.T) {
	for _, mode := range []string{"attach", "check"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := json.Marshal(RoutedIntegrityV3{Mode: mode, Selection: integrityWireRefV3()})
			req := RoutedRequestV3{RoutedProtocolV3, strings.Repeat("a", 32), 1, 22, "routed", "inspect", p}
			raw, _ := json.Marshal(req)
			if _, command, err := DecodeRoutedRequestV3(raw, req.Run, 22, 0); err != nil || command.Integrity.Mode != mode {
				t.Fatal(command, err)
			}
			payload, _ := json.Marshal(RoutedIntegrityResultV3{Mode: mode, Result: configpoc.IntegrityResultV1{Selection: integrityWireRefV3(), State: configpoc.IntegrityCompleteV1}})
			reply := RoutedReplyV3{RoutedProtocolV3, req.Run, 1, 22, "routed", "inspect", "", payload}
			encoded, _ := json.Marshal(reply)
			if _, result, err := DecodeRoutedReplyV3(encoded, req); err != nil || result.Integrity.State != configpoc.IntegrityCompleteV1 {
				t.Fatal(result, err)
			}
			opposite := "attach"
			if mode == "attach" {
				opposite = "check"
			}
			payload, _ = json.Marshal(RoutedIntegrityResultV3{Mode: opposite, Result: configpoc.IntegrityResultV1{Selection: integrityWireRefV3(), State: configpoc.IntegrityCompleteV1}})
			reply.Payload = payload
			encoded, _ = json.Marshal(reply)
			if _, _, err := DecodeRoutedReplyV3(encoded, req); err == nil {
				t.Fatal("cross-mode response accepted")
			}
		})
	}
	for _, change := range []string{"mode", "selection", "unknown", "ready"} {
		t.Run(change, func(t *testing.T) {
			payload := map[string]any{"mode": "check", "selection": integrityWireRefV3()}
			switch change {
			case "mode":
				payload["mode"] = "apply"
			case "selection":
				r := integrityWireRefV3()
				r.State = "bad"
				payload["selection"] = r
			case "unknown":
				payload["budget"] = 999999
			case "ready":
				payload["ready"] = true
			}
			p, _ := json.Marshal(payload)
			r := RoutedRequestV3{RoutedProtocolV3, strings.Repeat("a", 32), 1, 22, "routed", "inspect", p}
			raw, _ := json.Marshal(r)
			if _, _, err := DecodeRoutedRequestV3(raw, r.Run, 22, 0); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}
