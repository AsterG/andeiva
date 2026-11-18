package configpoc

import (
	"bytes"
	"encoding/json"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const v4RoutedDHCPConfigurationFeature = "configuration.routed-dhcp-configuration.v4"
const v4RoutedDHCPConfigurationLimit = 16 << 10

// A selected continuation binds configuration lineage, not a DHCP grant.
// Phase a has no producer, runtime capability or admission exception.
type v4RoutedDHCPConfigurationState struct {
	Version      int    `json:"version"`
	Continuation string `json:"continuation,omitempty"`
	Transition   string `json:"transition,omitempty"`
}

type v4RoutedDHCPConfigurationGroup struct {
	Work string `json:"work"`
	Side string `json:"side"`
}

// Replacement references the single shared acquisition contract required by
// ADR-072/074. This package must not invent a second identity or factory.
type v4RoutedDHCPConfigurationReplacement struct {
	Acquisition string `json:"acquisition"`
}

type v4RoutedDHCPConfiguration struct {
	Version         int                                   `json:"version"`
	Lineage         string                                `json:"lineage"`
	Kind            string                                `json:"kind"`
	Impact          string                                `json:"impact"`
	SourceWork      string                                `json:"source_dhcp_work"`
	SourceSelection SelectionReferenceV2                  `json:"source_selection"`
	Operation       string                                `json:"operation_id"`
	Subject         string                                `json:"subject"`
	Namespace       string                                `json:"namespace_id"`
	Fingerprint     string                                `json:"request_fingerprint"`
	Expected        uint64                                `json:"expected_generation,string"`
	Generation      uint64                                `json:"target_generation,string"`
	Before          string                                `json:"before_configuration"`
	Target          string                                `json:"target_configuration"`
	Group           *v4RoutedDHCPConfigurationGroup       `json:"group,omitempty"`
	Replacement     *v4RoutedDHCPConfigurationReplacement `json:"replacement,omitempty"`
}

// Finality is separate from the transition selected before Intent/effects.
// The transition never points back to this receipt or the final operation.
type v4RoutedDHCPConfigurationContinuation struct {
	Version       int    `json:"version"`
	Transition    string `json:"transition"`
	Operation     string `json:"operation"`
	Configuration string `json:"configuration"`
}

func validRoutedDHCPConfigurationShapeV4(x v4RoutedDHCPConfiguration) bool {
	if x.Version != 4 || x.Lineage == "" || len(x.Lineage) > 128 || !validHash(x.SourceWork) || x.Operation == "" || len(x.Operation) > 128 || x.Subject == "" || len(x.Subject) > 128 || x.Namespace == "" || len(x.Namespace) > 128 || !validHash(x.Fingerprint) || !validHash(x.Before) || !validHash(x.Target) || x.Expected == 0 || x.Generation < x.Expected || x.Generation-x.Expected > 1 {
		return false
	}
	s := x.SourceSelection
	if !validHash(s.Selection) || !validHash(s.State) || s.Previous != "" && !validHash(s.Previous) || s.Lineage != x.Lineage || s.Sequence == 0 || s.Generation != x.Expected || s.WorkHash != x.SourceWork || s.Mode != "dhcp-configuration-v4" {
		return false
	}
	if x.Kind == "metadata" {
		return x.Impact == "preserve" && x.Group == nil && x.Replacement == nil
	}
	if x.Kind != "grouped" || x.Group == nil || !validHash(x.Group.Work) || x.Group.Side != "target" && x.Group.Side != "before" {
		return false
	}
	return x.Impact == "preserve" && x.Replacement == nil || x.Impact == "replace" && x.Replacement != nil && validHash(x.Replacement.Acquisition)
}

func decodeRoutedDHCPConfigurationV4(raw []byte) (v4RoutedDHCPConfiguration, error) {
	var x v4RoutedDHCPConfiguration
	if len(raw) == 0 || len(raw) > v4RoutedDHCPConfigurationLimit || !jsoncheck.UniqueControlFields(raw) || checkpointDecode(raw, &x) != nil || !validRoutedDHCPConfigurationShapeV4(x) {
		return x, ErrRecovery
	}
	canonical, err := json.Marshal(x)
	if err != nil || !bytes.Equal(canonical, raw) {
		return v4RoutedDHCPConfiguration{}, ErrRecovery
	}
	return x, nil
}
