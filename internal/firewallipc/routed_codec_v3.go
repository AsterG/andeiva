package firewallipc

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

const RoutedProtocolV3 = 3
const RoutedIntegrityCapabilityV3 = "routed_integrity_gate.v1"

// A preparation contains three independently bounded artifacts. The additional
// envelope allowance is fixed; it is not negotiated by an administrative caller.
const RoutedFrameMaxV3 = 3*configpoc.RoutedArtifactLimit + 4096

func exactRoutedV3(data []byte, out any, required []string, optional ...string) error {
	return exactFrame(data, out, RoutedFrameMaxV3, required, optional...)
}

// RoutedReferenceV3 is a correlation expectation, never proof of selection.
// The helper must resolve it independently from its supervisor-pinned store.
type RoutedReferenceV3 struct {
	Work       string `json:"work"`
	Lineage    string `json:"lineage"`
	Generation string `json:"generation"`
}

func (r RoutedReferenceV3) Valid() bool {
	n, err := strconv.ParseUint(r.Generation, 10, 64)
	return hashV2(r.Work) && leaseV2.MatchString(r.Lineage) && err == nil && n != 0 && strconv.FormatUint(n, 10) == r.Generation
}

type RoutedHelloV3 struct {
	ProtocolVersion  int      `json:"protocol_version"`
	RuntimeRun       string   `json:"runtime_run"`
	Namespace        uint64   `json:"namespace"`
	Domain           string   `json:"domain"`
	RequiredFeatures []string `json:"required_features"`
	Run              string   `json:"run,omitempty"`
	Epoch            uint64   `json:"epoch,omitempty"`
}

func NewRoutedHelloV3(runtimeRun string, namespace uint64) RoutedHelloV3 {
	return RoutedHelloV3{ProtocolVersion: RoutedProtocolV3, RuntimeRun: runtimeRun, Namespace: namespace, Domain: "routed", RequiredFeatures: []string{"routed_selected.v1", "reader_profile.v1", "writer_fence.v1"}}
}
func DecodeRoutedHelloV3(data []byte, reply bool) (RoutedHelloV3, error) {
	var h RoutedHelloV3
	required := []string{"protocol_version", "runtime_run", "namespace", "domain", "required_features"}
	if reply {
		required = append(required, "run", "epoch")
	}
	if len(data) > RoutedFrameMaxV3 || exactRoutedV3(data, &h, required) != nil || h.ProtocolVersion != RoutedProtocolV3 || !runV2(h.RuntimeRun) || h.Namespace == 0 || h.Domain != "routed" || (len(h.RequiredFeatures) != 3 && len(h.RequiredFeatures) != 4 && len(h.RequiredFeatures) != 5) || (len(h.RequiredFeatures) >= 4 && h.RequiredFeatures[3] != RoutedIntegrityCapabilityV3) || (len(h.RequiredFeatures) == 5 && h.RequiredFeatures[4] != RoutedInventoryCapabilityV3) || h.RequiredFeatures[0] != "routed_selected.v1" || h.RequiredFeatures[1] != "reader_profile.v1" || h.RequiredFeatures[2] != "writer_fence.v1" || reply && (!runV2(h.Run) || h.Epoch == 0 || h.Epoch > 0xffffffff) {
		return RoutedHelloV3{}, ErrChannel
	}
	return h, nil
}

type RoutedRequestV3 struct {
	ProtocolVersion int             `json:"protocol_version"`
	Run             string          `json:"run"`
	Sequence        uint64          `json:"sequence"`
	Namespace       uint64          `json:"namespace"`
	Domain          string          `json:"domain"`
	Verb            string          `json:"verb"`
	Payload         json.RawMessage `json:"payload"`
}
type RoutedPrepareV3 struct {
	Target   configpoc.RoutedActivationBundleV1 `json:"target"`
	Baseline string                             `json:"baseline_revision"`
}
type RoutedSelectedV3 struct {
	Reference RoutedReferenceV3 `json:"reference"`
	Side      string            `json:"side,omitempty"`
}
type RoutedIntegrityResultV3 struct {
	Mode   string                      `json:"mode"`
	Result configpoc.IntegrityResultV1 `json:"result"`
}

type RoutedIntegrityV3 struct {
	Mode      string                         `json:"mode"`
	Selection configpoc.SelectionReferenceV2 `json:"selection"`
}

func ValidRoutedSelectionV3(r configpoc.SelectionReferenceV2) bool {
	if !hashV2(r.Selection) || !hashV2(r.State) || (r.Previous != "" && !hashV2(r.Previous)) || !leaseV2.MatchString(r.Lineage) || r.Sequence == 0 || r.Generation == 0 {
		return false
	}
	if r.Mode == "prepare" {
		return r.WorkHash == ""
	}
	return (r.Mode == "intent" || r.Mode == "pending" || r.Mode == "active") && hashV2(r.WorkHash)
}
func ValidRoutedIntegrityResultV3(r configpoc.IntegrityResultV1) bool {
	switch r.State {
	case configpoc.IntegrityCompleteV1:
		return ValidRoutedSelectionV3(r.Selection)
	case configpoc.IntegrityCancelledV1, configpoc.IntegrityStaleV1, configpoc.IntegrityUnavailableV1, configpoc.IntegrityFencedV1:
		return r.Selection == (configpoc.SelectionReferenceV2{}) || ValidRoutedSelectionV3(r.Selection)
	default:
		return false
	}
}

type RoutedCommandV3 struct {
	Integrity RoutedIntegrityV3
	Verb      string
	Target    configpoc.RoutedActivationBundleV1
	Reference RoutedReferenceV3
	Side      string
	Baseline  string
}

func canonicalBundleV3(b configpoc.RoutedActivationBundleV1) bool {
	rebuilt, e := configpoc.NewRoutedActivationBundleV1(b.Firewall, b.LocalServices)
	if e != nil {
		return false
	}
	a, e := json.Marshal(rebuilt)
	if e != nil {
		return false
	}
	raw, e := json.Marshal(b)
	return e == nil && string(a) == string(raw)
}

// DecodeRoutedRequestV3 accepts no serialized plan, paths, identities, TTL or
// privileged command. Preparation is read-only; effects require a durable work
// reference which is independently resolved immediately before dispatch.
func DecodeRoutedRequestV3(data []byte, run string, namespace, last uint64) (RoutedRequestV3, RoutedCommandV3, error) {
	var r RoutedRequestV3
	var c RoutedCommandV3
	if len(data) > RoutedFrameMaxV3 || exactRoutedV3(data, &r, []string{"protocol_version", "run", "sequence", "namespace", "domain", "verb", "payload"}) != nil || r.ProtocolVersion != RoutedProtocolV3 || !runV2(run) || r.Run != run || namespace == 0 || r.Namespace != namespace || last == ^uint64(0) || r.Sequence != last+1 || r.Domain != "routed" {
		return r, c, ErrChannel
	}
	c.Verb = r.Verb
	switch r.Verb {
	case "inspect":
		var p RoutedIntegrityV3
		if exactRoutedV3(r.Payload, &p, []string{"mode", "selection"}) != nil || (p.Mode != "attach" && p.Mode != "check") || !ValidRoutedSelectionV3(p.Selection) {
			return r, RoutedCommandV3{}, ErrChannel
		}
		c.Integrity = p
	case "observe", "inventory":
		var empty struct{}
		if exactRoutedV3(r.Payload, &empty, nil) != nil {
			return r, RoutedCommandV3{}, ErrChannel
		}
	case "prepare", "prepare_boot":
		var p RoutedPrepareV3
		if exactRoutedV3(r.Payload, &p, []string{"target", "baseline_revision"}) != nil || !canonicalBundleV3(p.Target) || p.Baseline != "" && !hashV2(p.Baseline) || r.Verb == "prepare_boot" && p.Baseline == "" {
			return r, RoutedCommandV3{}, ErrChannel
		}
		c.Target, c.Baseline = p.Target, p.Baseline
	case "match", "resume", "arm", "apply", "confirm", "recover", "bootstrap":
		var p RoutedSelectedV3
		required := []string{"reference"}
		if r.Verb == "match" {
			required = append(required, "side")
		}
		if exactRoutedV3(r.Payload, &p, required) != nil || !p.Reference.Valid() {
			return r, RoutedCommandV3{}, ErrChannel
		}
		if r.Verb == "match" {
			if p.Side != "before" && p.Side != "target" {
				return r, RoutedCommandV3{}, ErrChannel
			}
		} else if p.Side != "" {
			return r, RoutedCommandV3{}, ErrChannel
		}
		c.Reference, c.Side = p.Reference, p.Side
	default:
		return r, RoutedCommandV3{}, ErrChannel
	}
	return r, c, nil
}

func routedErrorV3(code string) bool {
	return code == "" || code == "ANDEIVA_ADMIN_HELPER_UNAVAILABLE" || code == "ANDEIVA_CONFIG_RECOVERY_REQUIRED" || code == "ANDEIVA_CONFIG_CONFLICT"
}

type RoutedReplyV3 struct {
	ProtocolVersion int             `json:"protocol_version"`
	Run             string          `json:"run"`
	Sequence        uint64          `json:"sequence"`
	Namespace       uint64          `json:"namespace"`
	Domain          string          `json:"domain"`
	Verb            string          `json:"verb"`
	Error           string          `json:"error"`
	Payload         json.RawMessage `json:"payload"`
}
type RoutedObservedV3 struct {
	Receipt  RoutedReceiptV3 `json:"receipt"`
	Revision string          `json:"revision"`
}
type RoutedReceiptV3 struct {
	Phase    string    `json:"phase"`
	ID       string    `json:"id"`
	Previous string    `json:"previous"`
	Target   string    `json:"target"`
	Deadline time.Time `json:"deadline"`
}
type RoutedPreparedV3 struct {
	Preparation configpoc.RoutedPreparationV1 `json:"preparation"`
}
type RoutedResultV3 struct {
	Inventory   networkinventory.Snapshot
	Integrity   configpoc.IntegrityResultV1
	Observed    RoutedObservedV3
	Preparation configpoc.RoutedPreparationV1
}

func DecodeRoutedReplyV3(data []byte, request RoutedRequestV3) (RoutedReplyV3, RoutedResultV3, error) {
	var reply RoutedReplyV3
	var result RoutedResultV3
	if len(data) > RoutedFrameMaxV3 || exactRoutedV3(data, &reply, []string{"protocol_version", "run", "sequence", "namespace", "domain", "verb", "error", "payload"}) != nil || reply.ProtocolVersion != RoutedProtocolV3 || reply.Run != request.Run || reply.Sequence != request.Sequence || reply.Namespace != request.Namespace || reply.Domain != "routed" || reply.Verb != request.Verb || !routedErrorV3(reply.Error) {
		return reply, result, ErrChannel
	}
	if reply.Error != "" {
		var empty struct{}
		if exactRoutedV3(reply.Payload, &empty, nil) != nil {
			return reply, result, ErrChannel
		}
		return reply, result, nil
	}
	switch reply.Verb {
	case "inventory":
		value, e := decodeRoutedInventoryV3(reply.Payload)
		if e != nil {
			return reply, result, e
		}
		result.Inventory = value
	case "inspect":
		var value RoutedIntegrityResultV3
		var expected RoutedIntegrityV3
		if exactRoutedV3(request.Payload, &expected, []string{"mode", "selection"}) != nil || (expected.Mode != "attach" && expected.Mode != "check") || !ValidRoutedSelectionV3(expected.Selection) || exactRoutedV3(reply.Payload, &value, []string{"mode", "result"}) != nil || value.Mode != expected.Mode || !ValidRoutedIntegrityResultV3(value.Result) || (value.Result.State == configpoc.IntegrityCompleteV1 && value.Result.Selection != expected.Selection) {
			return reply, result, ErrChannel
		}
		result.Integrity = value.Result
	case "observe":
		var value RoutedObservedV3
		if exactRoutedV3(reply.Payload, &value, []string{"receipt", "revision"}) != nil || !validRoutedReceiptV3(value.Receipt) || value.Revision != "" && !hashV2(value.Revision) {
			return reply, result, ErrChannel
		}
		result.Observed = value
	case "prepare", "prepare_boot":
		var value RoutedPreparedV3
		if exactRoutedV3(reply.Payload, &value, []string{"preparation"}) != nil {
			return reply, result, ErrChannel
		}
		before, e := configpoc.CanonicalOwned(value.Preparation.Before)
		if e != nil {
			return reply, result, ErrChannel
		}
		after, e := configpoc.CanonicalOwned(value.Preparation.Target)
		if e != nil {
			return reply, result, ErrChannel
		}
		deps, e := configpoc.CanonicalDependencies(value.Preparation.Dependencies)
		if e != nil || !configpoc.RoutedOwnershipMatchesDependencies(before, deps) || !configpoc.RoutedOwnershipMatchesDependencies(after, deps) {
			return reply, result, ErrChannel
		}
		result.Preparation = configpoc.RoutedPreparationV1{Before: before, Target: after, Dependencies: deps}
	case "match", "resume", "arm", "apply", "confirm", "recover", "bootstrap":
		var empty struct{}
		if exactRoutedV3(reply.Payload, &empty, nil) != nil {
			return reply, result, ErrChannel
		}
	default:
		return reply, result, ErrChannel
	}
	return reply, result, nil
}
func validRoutedReceiptV3(r RoutedReceiptV3) bool {
	switch r.Phase {
	case "bootstrap", "idle", "armed", "pending", "expired", "blocked":
	default:
		return false
	}
	if r.ID == "" {
		return r.Previous == "" && r.Target == "" && r.Deadline.IsZero() && (r.Phase == "bootstrap" || r.Phase == "idle" || r.Phase == "blocked")
	}
	return r.Phase != "bootstrap" && leaseV2.MatchString(r.ID) && hashV2(r.Target) && (r.Previous == "" || hashV2(r.Previous)) && !r.Deadline.IsZero()
}
