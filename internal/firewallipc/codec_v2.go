package firewallipc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

const ProtocolV2 = 2

var leaseV2 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type RecoveryScope struct {
	ID       string    `json:"id"`
	Previous string    `json:"previous"`
	Target   string    `json:"target"`
	Deadline time.Time `json:"deadline"`
}
type ObservedScope struct {
	State firewalladmin.LeaseState `json:"state"`
	Hash  string                   `json:"hash"`
}
type RequestV2 struct {
	ProtocolVersion int             `json:"protocol_version"`
	Run             string          `json:"run"`
	Sequence        uint64          `json:"sequence"`
	Namespace       uint64          `json:"namespace"`
	Domain          string          `json:"domain"`
	Verb            string          `json:"verb"`
	Payload         json.RawMessage `json:"payload"`
}
type ReplyV2 struct {
	ProtocolVersion int             `json:"protocol_version"`
	Run             string          `json:"run"`
	Sequence        uint64          `json:"sequence"`
	Namespace       uint64          `json:"namespace"`
	Domain          string          `json:"domain"`
	Verb            string          `json:"verb"`
	Error           string          `json:"error"`
	Payload         json.RawMessage `json:"payload"`
}
type RevisionPayloadV2 struct {
	Revision configpoc.Revision `json:"revision"`
}
type ArmPayloadV2 struct {
	ID       string             `json:"id"`
	Previous configpoc.Revision `json:"previous"`
	Target   configpoc.Revision `json:"target"`
	TTL      time.Duration      `json:"ttl_ns"`
}
type ConfirmPayloadV2 struct {
	ID     string `json:"id"`
	Target string `json:"target"`
}
type ArmUntilPayloadV2 struct {
	ID       string             `json:"id"`
	Previous configpoc.Revision `json:"previous"`
	Target   configpoc.Revision `json:"target"`
	Deadline time.Time          `json:"deadline"`
}
type ApplyScopedPayloadV2 struct {
	Revision configpoc.Revision `json:"revision"`
	Scope    RecoveryScope      `json:"recovery_scope"`
}
type ResultV2 struct {
	State         firewalladmin.LeaseState `json:"state"`
	Hash          string                   `json:"hash"`
	Artifact      string                   `json:"artifact,omitempty"`
	Counters      []Counter                `json:"counters,omitempty"`
	CounterEpoch  string                   `json:"counter_epoch,omitempty"`
	Local         *localpolicy.Observation `json:"local,omitempty"`
	RecoveryScope *RecoveryScope           `json:"recovery_scope,omitempty"`
	ObservedScope *ObservedScope           `json:"observed_scope,omitempty"`
}
type CommandV2 struct {
	Revision    configpoc.Revision
	Arm         ArmPayloadV2
	Confirm     ConfirmPayloadV2
	Recovery    RecoveryScope
	Observed    ObservedScope
	ArmUntil    ArmUntilPayloadV2
	ApplyScoped ApplyScopedPayloadV2
}

func hashV2(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func runV2(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}
func DomainV2(s string) bool { return s == "firewall" || s == "local_services" }
func validRevisionV2(r configpoc.Revision) bool {
	c, e := configpoc.Canonical(r.Config)
	return e == nil && c.Hash == r.Hash
}

// exactV2 preserves strict duplicate/depth/unknown checks and rejects Go's
// otherwise case-insensitive matching of the security envelope and payload.
func exactV2(data []byte, out any, required []string, optional ...string) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || decodeBounded(data, out, LocalReplyMaxFrame) != nil {
		return ErrChannel
	}
	if !canonicalKeysV2(data, reflect.TypeOf(out)) {
		return ErrChannel
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return ErrChannel
	}
	allowed := map[string]bool{}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return ErrChannel
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			return ErrChannel
		}
	}
	return nil
}

func canonicalKeysV2(data []byte, kind reflect.Type) bool {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == reflect.TypeFor[time.Time]() || kind == reflect.TypeFor[json.RawMessage]() {
		return true
	}
	switch kind.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil {
			return false
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			allowed[name] = field.Type
		}
		for name, value := range fields {
			field, ok := allowed[name]
			if !ok || !canonicalKeysV2(value, field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if kind.Elem().Kind() == reflect.Uint8 {
			return true
		}
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return false
		}
		for _, value := range values {
			if !canonicalKeysV2(value, kind.Elem()) {
				return false
			}
		}
	}
	return true
}
func canonicalTimeV2(data []byte, key string, value time.Time) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	encoded, _ := json.Marshal(value.UTC())
	return bytes.Equal(fields[key], encoded)
}
func validRecoveryV2(s RecoveryScope) bool {
	return leaseV2.MatchString(s.ID) && hashV2(s.Previous) && hashV2(s.Target) && !s.Deadline.IsZero()
}
func ValidObservedV2(o ObservedScope) bool {
	s := o.State
	if s.Phase == "bootstrap" {
		return o.Hash == "" && s.ID == "" && s.Previous == "" && s.Target == "" && s.Deadline.IsZero()
	}
	if !hashV2(o.Hash) {
		return false
	}
	if s.Phase == "idle" && s.ID == "" {
		return s.Previous == "" && s.Target == "" && s.Deadline.IsZero()
	}
	if s.Phase != "idle" && s.Phase != "armed" && s.Phase != "pending" && s.Phase != "expired" {
		return false
	}
	if !validRecoveryV2(RecoveryScope{s.ID, s.Previous, s.Target, s.Deadline}) {
		return false
	}
	if s.Phase == "armed" || s.Phase == "expired" {
		return o.Hash == s.Previous
	}
	return o.Hash == s.Target
}
func decodeObservedV2(data []byte, out *ObservedScope) error {
	if exactV2(data, out, []string{"state", "hash"}) != nil {
		return ErrChannel
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	var state firewalladmin.LeaseState
	if exactV2(fields["state"], &state, []string{"phase", "id", "previous", "target", "deadline"}) != nil || !canonicalTimeV2(fields["state"], "deadline", state.Deadline) || !ValidObservedV2(*out) {
		return ErrChannel
	}
	return nil
}
func DecodeRequestV2(data []byte) (RequestV2, CommandV2, error) {
	var m RequestV2
	var p CommandV2
	if len(data) > MaxFrame || exactV2(data, &m, []string{"protocol_version", "run", "sequence", "namespace", "domain", "verb", "payload"}) != nil || m.ProtocolVersion != 2 || !runV2(m.Run) || m.Sequence>>32 == 0 || m.Sequence&0xffffffff == 0 || m.Namespace == 0 || !DomainV2(m.Domain) {
		return m, p, ErrChannel
	}
	switch m.Verb {
	case "state", "observe":
		if exactV2(m.Payload, &struct{}{}, nil) != nil {
			return m, p, ErrChannel
		}
	case "bootstrap", "apply":
		var v RevisionPayloadV2
		if exactV2(m.Payload, &v, []string{"revision"}) != nil || !validRevisionV2(v.Revision) {
			return m, p, ErrChannel
		}
		p.Revision = v.Revision
	case "arm":
		if exactV2(m.Payload, &p.Arm, []string{"id", "previous", "target", "ttl_ns"}) != nil || !leaseV2.MatchString(p.Arm.ID) || !validRevisionV2(p.Arm.Previous) || !validRevisionV2(p.Arm.Target) || p.Arm.TTL < 500*time.Millisecond || p.Arm.TTL > 120*time.Second {
			return m, p, ErrChannel
		}
	case "arm_until":
		if exactV2(m.Payload, &p.ArmUntil, []string{"id", "previous", "target", "deadline"}) != nil || !leaseV2.MatchString(p.ArmUntil.ID) || !validRevisionV2(p.ArmUntil.Previous) || !validRevisionV2(p.ArmUntil.Target) || p.ArmUntil.Deadline.IsZero() || !canonicalTimeV2(m.Payload, "deadline", p.ArmUntil.Deadline) {
			return m, p, ErrChannel
		}
	case "apply_scoped":
		if exactV2(m.Payload, &p.ApplyScoped, []string{"revision", "recovery_scope"}) != nil || !validRevisionV2(p.ApplyScoped.Revision) {
			return m, p, ErrChannel
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(m.Payload, &raw)
		if exactV2(raw["recovery_scope"], &p.ApplyScoped.Scope, []string{"id", "previous", "target", "deadline"}) != nil || !validRecoveryV2(p.ApplyScoped.Scope) || !canonicalTimeV2(raw["recovery_scope"], "deadline", p.ApplyScoped.Scope.Deadline) || p.ApplyScoped.Revision.Hash != p.ApplyScoped.Scope.Target {
			return m, p, ErrChannel
		}
	case "confirm":
		if exactV2(m.Payload, &p.Confirm, []string{"id", "target"}) != nil || !leaseV2.MatchString(p.Confirm.ID) || !hashV2(p.Confirm.Target) {
			return m, p, ErrChannel
		}
	case "recover_scoped", "confirm_scoped":
		if exactV2(m.Payload, &p.Recovery, []string{"id", "previous", "target", "deadline"}) != nil || !validRecoveryV2(p.Recovery) || !canonicalTimeV2(m.Payload, "deadline", p.Recovery.Deadline) {
			return m, p, ErrChannel
		}
	case "attach_observed":
		if decodeObservedV2(m.Payload, &p.Observed) != nil {
			return m, p, ErrChannel
		}
	default:
		return m, p, ErrChannel
	}
	return m, p, nil
}

func DecodeReplyV2(data []byte, request RequestV2) (ResultV2, error) {
	var reply ReplyV2
	var result ResultV2
	limit := MaxFrame
	if request.Domain == "local_services" {
		limit = LocalReplyMaxFrame
	}
	if len(data) > limit || exactV2(data, &reply, []string{"protocol_version", "run", "sequence", "namespace", "domain", "verb", "error", "payload"}) != nil || reply.ProtocolVersion != 2 || reply.Run != request.Run || reply.Sequence != request.Sequence || reply.Namespace != request.Namespace || reply.Domain != request.Domain || reply.Verb != request.Verb {
		return ResultV2{}, ErrChannel
	}
	if reply.Error != "" {
		if reply.Error != ErrChannel.Error() || exactV2(reply.Payload, &struct{}{}, nil) != nil {
			return ResultV2{}, ErrChannel
		}
		return ResultV2{}, ErrChannel
	}
	optional := []string{}
	switch request.Verb {
	case "bootstrap", "apply", "arm", "arm_until", "apply_scoped":
		optional = []string{"artifact"}
	case "recover_scoped":
		optional = []string{"recovery_scope"}
	case "attach_observed":
		optional = []string{"observed_scope"}
	case "observe":
		if request.Domain == "local_services" {
			optional = []string{"local"}
		} else {
			optional = []string{"counters", "counter_epoch"}
		}
	}
	if exactV2(reply.Payload, &result, []string{"state", "hash"}, optional...) != nil {
		return ResultV2{}, ErrChannel
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(reply.Payload, &fields)
	observed, _ := json.Marshal(map[string]json.RawMessage{"state": fields["state"], "hash": fields["hash"]})
	if decodeObservedV2(observed, &ObservedScope{}) != nil {
		return ResultV2{}, ErrChannel
	}
	if (request.Verb == "bootstrap" || request.Verb == "apply" || request.Verb == "arm" || request.Verb == "arm_until" || request.Verb == "apply_scoped") && !hashV2(result.Artifact) {
		return ResultV2{}, ErrChannel
	}
	if request.Verb == "observe" {
		if result.Hash == "" {
			return ResultV2{}, ErrChannel
		}
		if request.Domain == "local_services" {
			if !validLocalObservation(Reply{Hash: result.Hash, Local: result.Local}) {
				return ResultV2{}, ErrChannel
			}
		} else {
			if _, ok := counterEpochGeneration(result.CounterEpoch, request.Run); !ok {
				return ResultV2{}, ErrChannel
			}
		}
	}
	if request.Verb == "recover_scoped" {
		var expected RecoveryScope
		var scope RecoveryScope
		if exactV2(fields["recovery_scope"], &scope, []string{"id", "previous", "target", "deadline"}) != nil || !canonicalTimeV2(fields["recovery_scope"], "deadline", scope.Deadline) || json.Unmarshal(request.Payload, &expected) != nil || result.RecoveryScope == nil || !sameRecoveryV2(expected, *result.RecoveryScope) || result.State.Phase != "idle" || result.State.ID != "" || result.Hash != expected.Previous {
			return ResultV2{}, ErrChannel
		}
	}
	if request.Verb == "attach_observed" {
		var expected ObservedScope
		_ = json.Unmarshal(request.Payload, &expected)
		var scope ObservedScope
		if decodeObservedV2(fields["observed_scope"], &scope) != nil || result.ObservedScope == nil || !sameObservedV2(expected, *result.ObservedScope) || !sameObservedV2(expected, ObservedScope{result.State, result.Hash}) {
			return ResultV2{}, ErrChannel
		}
	}
	if request.Verb == "bootstrap" || request.Verb == "apply" {
		var p RevisionPayloadV2
		_ = json.Unmarshal(request.Payload, &p)
		if result.Hash != p.Revision.Hash {
			return ResultV2{}, ErrChannel
		}
	}
	if request.Verb == "confirm" {
		var p ConfirmPayloadV2
		_ = json.Unmarshal(request.Payload, &p)
		if result.State.Phase != "idle" || result.State.ID != p.ID || result.State.Target != p.Target || result.Hash != p.Target {
			return ResultV2{}, ErrChannel
		}
	}
	if request.Verb == "arm_until" || request.Verb == "apply_scoped" || request.Verb == "confirm_scoped" {
		var expected RecoveryScope
		switch request.Verb {
		case "arm_until":
			var p ArmUntilPayloadV2
			_ = json.Unmarshal(request.Payload, &p)
			expected = RecoveryScope{p.ID, p.Previous.Hash, p.Target.Hash, p.Deadline}
		case "apply_scoped":
			var p ApplyScopedPayloadV2
			_ = json.Unmarshal(request.Payload, &p)
			expected = p.Scope
		case "confirm_scoped":
			_ = json.Unmarshal(request.Payload, &expected)
		}
		actual := RecoveryScope{result.State.ID, result.State.Previous, result.State.Target, result.State.Deadline}
		phase := map[string]string{"arm_until": "armed", "apply_scoped": "pending", "confirm_scoped": "idle"}[request.Verb]
		if !sameRecoveryV2(expected, actual) || result.State.Phase != phase {
			return ResultV2{}, ErrChannel
		}
		want := expected.Target
		if request.Verb == "arm_until" {
			want = expected.Previous
		}
		if result.Hash != want {
			return ResultV2{}, ErrChannel
		}
	}
	return result, nil
}
func sameRecoveryV2(a, b RecoveryScope) bool {
	return a.ID == b.ID && a.Previous == b.Previous && a.Target == b.Target && a.Deadline.Equal(b.Deadline)
}
func sameObservedV2(a, b ObservedScope) bool {
	return a.Hash == b.Hash && a.State.Phase == b.State.Phase && a.State.ID == b.State.ID && a.State.Previous == b.State.Previous && a.State.Target == b.State.Target && a.State.Deadline.Equal(b.State.Deadline)
}
