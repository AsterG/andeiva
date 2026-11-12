package adminapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedCurrentDTODecimalGenerationsAndSeparateViews(t *testing.T) {
	high := ^uint64(0)
	input := configpoc.CurrentV2{Domain: "routed", DomainGenerations: &configpoc.DomainGenerationsV2{Firewall: high, LocalServices: high - 1, Network: high}, Snapshot: configpoc.Snapshot{Generation: high}, Routed: &configpoc.RoutedCurrentV2{SchemaVersion: 7, LocalServices: configpoc.Snapshot{Generation: high - 1}}}
	output := currentDTOv2(input)
	data, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"firewall":"18446744073709551615"`, `"local_services":"18446744073709551614"`, `"network":"18446744073709551615"`, `"domain":"routed"`, `"schema_version":7`} {
		if !strings.Contains(string(data), field) {
			t.Fatal("missing canonical routed projection", field, string(data))
		}
	}
	if output.Snapshot.Generation != DecimalV2(high) || output.Routed.LocalServices.Generation != DecimalV2(high-1) {
		t.Fatal("component generations mixed")
	}
	legacy, err := json.Marshal(currentDTOv2(configpoc.CurrentV2{Domain: "firewall"}))
	if err != nil || strings.Contains(string(legacy), "routed") || strings.Contains(string(legacy), "domain_generations") {
		t.Fatal("legacy DTO gained opted-in fields", err)
	}
}

func TestRoutedRequestDTOAdditiveLocalConfiguration(t *testing.T) {
	local := &configpoc.Config{SchemaVersion: 3}
	request := OperationRequestV2{Operation: configpoc.OpStage, LocalServicesConfig: local}.canonical()
	if request.Kind != configpoc.OpStage || request.LocalServicesConfig != local {
		t.Fatal("optional local configuration lost")
	}
	data, err := json.Marshal(OperationRequestV2{Operation: configpoc.OpValidate})
	if err != nil || string(data) != `{"operation":"validate"}` {
		t.Fatal("legacy request encoding changed", err, string(data))
	}
}
