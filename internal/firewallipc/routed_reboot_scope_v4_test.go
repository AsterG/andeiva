package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedRebootScopeV4NegotiatesSeparateProfile(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		h := NewRoutedHelloV3(strings.Repeat("a", 32), 200)
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3)
		if dhcp {
			h.RequiredFeatures = append(h.RequiredFeatures, RoutedDHCPCapabilityV3)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedRebootScopeCapabilityV4)
		raw, _ := json.Marshal(h)
		got, err := DecodeRoutedHelloV3(raw, false)
		if err != nil || !got.HasCapability(RoutedRebootScopeCapabilityV4) || got.HasCapability(RoutedFreshScopeCapabilityV3) {
			t.Fatal("v4 profile", err)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedFreshScopeCapabilityV3)
		raw, _ = json.Marshal(h)
		if _, err = DecodeRoutedHelloV3(raw, false); err == nil {
			t.Fatal("mixed v3/v4 profile accepted")
		}
	}
}

func TestRoutedRebootScopeV4RequestCannotSupplyBootOrProof(t *testing.T) {
	run := strings.Repeat("a", 32)
	for _, extra := range []string{"", `,"new_boot":true`, `,"old":{}`, `,"observed_at_new_boot_ns":1`, `,"evidence":{}`} {
		r := RoutedRequestV3{ProtocolVersion: 3, Run: run, Sequence: 1, Namespace: 200, Domain: "routed", Verb: "reboot_scope", Payload: json.RawMessage(`{"work":"` + strings.Repeat("b", 64) + `"` + extra + `}`)}
		raw, _ := json.Marshal(r)
		_, _, err := DecodeRoutedRequestV3(raw, run, 200, 0)
		if (err == nil) != (extra == "") {
			t.Fatal("unexpected request authority", extra, err)
		}
	}
}

func TestRoutedRebootScopeV4ReplyCarriesBootAttestationWithoutDrainTime(t *testing.T) {
	run, work := strings.Repeat("a", 32), strings.Repeat("b", 64)
	request := RoutedRequestV3{ProtocolVersion: 3, Run: run, Sequence: 1, Namespace: 200, Domain: "routed", Verb: "reboot_scope", Payload: json.RawMessage(`{"work":"` + work + `"}`)}
	evidence := func(attested bool, drained int64) json.RawMessage {
		value := map[string]any{
			"version": 4, "work": work, "receipt_sha256": strings.Repeat("c", 64), "metadata_sha256": strings.Repeat("d", 64),
			"drained_at_old_boot_ns": drained, "observed_at_new_boot_ns": 1, "before": strings.Repeat("e", 64), "dependencies": strings.Repeat("f", 64),
			"old": map[string]any{"uid": 62002, "gid": 62003, "target_namespace": 42, "host_namespace": 40, "boot_id": "12345678-1234-1234-1234-123456789abc", "run_id": strings.Repeat("1", 32)},
			"new": map[string]any{"uid": 62002, "gid": 62003, "target_namespace": 200, "host_namespace": 40, "boot_id": "22345678-1234-1234-1234-123456789abc", "run_id": run},
		}
		if attested {
			value["boot_attested"] = true
		}
		raw, _ := json.Marshal(map[string]any{"evidence": value})
		return raw
	}
	for name, c := range map[string]struct {
		attested bool
		drained  int64
		accepted bool
	}{
		"drain receipt":                 {false, 7, true},
		"boot attestation":              {true, 0, true},
		"attestation with a drain time": {true, 7, false},
		"receipt without a drain time":  {false, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			reply := RoutedReplyV3{ProtocolVersion: RoutedProtocolV3, Run: run, Sequence: 1, Namespace: 200, Domain: "routed", Verb: "reboot_scope", Payload: evidence(c.attested, c.drained)}
			raw, err := json.Marshal(reply)
			if err != nil {
				t.Fatal(err)
			}
			_, result, err := DecodeRoutedReplyV3(raw, request)
			if (err == nil) != c.accepted || c.accepted && result.RebootScope.BootAttested != c.attested {
				t.Fatal("unexpected reboot evidence decision", err)
			}
		})
	}
}
