package networkexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const leaseGateTable = "andeiva_lease_gate"
const leaseGateMaxJSON = 32 << 10

type leaseGateObject = map[string]any

func leaseGateRef(name string) leaseGateObject {
	return leaseGateObject{"family": "inet", "table": leaseGateTable, "name": name}
}

func leaseGateObjects(wan string) []any {
	objects := []any{
		leaseGateObject{"table": leaseGateObject{"family": "inet", "name": leaseGateTable}},
		leaseGateObject{"set": leaseGateObject{"family": "inet", "table": leaseGateTable, "name": "enabled", "type": "ifname", "size": 1}},
		leaseGateObject{"set": leaseGateObject{"family": "inet", "table": leaseGateTable, "name": "live", "type": "ifname", "flags": []any{"timeout"}, "size": 1}},
		leaseGateObject{"chain": leaseGateObject{"family": "inet", "table": leaseGateTable, "name": "forward", "type": "filter", "hook": "forward", "prio": -300, "policy": "accept"}},
	}
	match := func(key, op string, right any) any {
		return leaseGateObject{"match": leaseGateObject{"op": op, "left": leaseGateObject{"meta": leaseGateObject{"key": key}}, "right": right}}
	}
	for _, key := range []string{"iifname", "oifname"} {
		for _, check := range []any{match("nfproto", "!=", "ipv4"), match(key, "!=", "@enabled"), match(key, "!=", "@live")} {
			objects = append(objects, leaseGateObject{"rule": leaseGateObject{"family": "inet", "table": leaseGateTable, "chain": "forward", "expr": []any{match(key, "==", wan), check, leaseGateObject{"drop": nil}}}})
		}
	}
	return objects
}

func leaseGateEncode(commands []any) []byte {
	b, _ := json.Marshal(leaseGateObject{"nftables": commands})
	return b
}

func leaseGateCreate(wan string) []byte {
	objects := leaseGateObjects(wan)
	commands := make([]any, 0, len(objects))
	for i, o := range objects {
		verb := "add"
		if i == 0 {
			verb = "create"
		}
		commands = append(commands, leaseGateObject{verb: o})
	}
	return leaseGateEncode(commands)
}

func leaseGateClose() []byte {
	return leaseGateEncode([]any{
		leaseGateObject{"flush": leaseGateObject{"set": leaseGateRef("enabled")}},
		leaseGateObject{"flush": leaseGateObject{"set": leaseGateRef("live")}},
	})
}

func leaseGateStage(wan, digest string, ttl int64) []byte {
	ref := leaseGateRef("live")
	ref["elem"] = []any{leaseGateObject{"elem": leaseGateObject{"val": wan, "timeout": ttl, "comment": digest}}}
	return leaseGateEncode([]any{leaseGateObject{"add": leaseGateObject{"element": ref}}})
}

func leaseGateOpen(wan string) []byte {
	ref := leaseGateRef("enabled")
	ref["elem"] = []any{wan}
	return leaseGateEncode([]any{leaseGateObject{"add": leaseGateObject{"element": ref}}})
}

// read validates every object, expression and rule order. Only numeric kernel
// handles and bounded metainfo are discarded. Expiry is an integer number of
// seconds; add one second to conservatively cover JSON truncation/rounding.
func (g *LeaseGate) read(ctx context.Context, enabled, token bool) (int64, error) {
	b, err := g.kernel.Observe(ctx)
	received, clockErr := g.now()
	if err != nil || clockErr != nil || received <= 0 {
		return 0, ErrObservation
	}
	remaining, err := leaseGateRead(b, g.wan.Binding.Name, enabled, token, leaseGateDigest(g.staged), g.timeout)
	if err != nil {
		return 0, err
	}
	if token {
		// Bounds are checked before multiplying, and subtraction avoids overflow.
		deadline := g.staged.Fact.DeadlineBootNS
		if remaining <= 0 || remaining > int64(7*24*time.Hour/time.Second) || deadline <= received || (remaining+1)*int64(time.Second) > deadline-received {
			return 0, ErrLeaseGate
		}
	}
	return received, nil
}

func leaseGateRead(b []byte, wan string, enabled, token bool, digest string, ttl int64) (int64, error) {
	if len(b) == 0 || len(b) > leaseGateMaxJSON || !jsoncheck.UniqueFields(b) {
		return 0, ErrObservation
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var root map[string]any
	if d.Decode(&root) != nil || len(root) != 1 {
		return 0, ErrObservation
	}
	items, ok := root["nftables"].([]any)
	if !ok || len(items) > 11 {
		return 0, ErrObservation
	}
	clean := make([]any, 0, len(items))
	var remaining int64
	metaSeen := false
	for _, item := range items {
		o, ok := item.(map[string]any)
		if !ok || len(o) != 1 {
			return 0, ErrObservation
		}
		if meta, exists := o["metainfo"]; exists {
			if metaSeen || len(clean) != 0 || !leaseGateMetainfo(meta) {
				return 0, ErrObservation
			}
			metaSeen = true
			continue
		}
		for kind, raw := range o {
			v, ok := raw.(map[string]any)
			if !ok {
				return 0, ErrObservation
			}
			if h, exists := v["handle"]; exists {
				if _, ok := leaseGateNumber(h); !ok {
					return 0, ErrObservation
				}
				delete(v, "handle")
			}
			if kind == "set" {
				elements, exists := v["elem"]
				name := v["name"]
				want := name == "enabled" && enabled || name == "live" && token
				if exists {
					a, ok := elements.([]any)
					if !ok || len(a) > 1 || (want && len(a) != 1) || (!want && len(a) != 0) {
						return 0, ErrObservation
					}
					if want && name == "enabled" && a[0] != wan {
						return 0, ErrObservation
					}
					if want && name == "live" {
						outer, ok := a[0].(map[string]any)
						if !ok || len(outer) != 1 {
							return 0, ErrObservation
						}
						e, ok := outer["elem"].(map[string]any)
						if !ok || len(e) != 4 || e["val"] != wan || e["comment"] != digest {
							return 0, ErrObservation
						}
						timeout, ok := leaseGateNumber(e["timeout"])
						if !ok || timeout != ttl {
							return 0, ErrObservation
						}
						remaining, ok = leaseGateNumber(e["expires"])
						if !ok || remaining <= 0 || remaining > timeout {
							return 0, ErrObservation
						}
					}
					delete(v, "elem")
				} else if want {
					return 0, ErrObservation
				}
			}
		}
		clean = append(clean, o)
	}
	// Round-trip the expected projection to use json.Number on both sides.
	expectedBytes := leaseGateEncode(leaseGateObjects(wan))
	var expected map[string]any
	decoder := json.NewDecoder(bytes.NewReader(expectedBytes))
	decoder.UseNumber()
	if decoder.Decode(&expected) != nil || !reflect.DeepEqual(clean, expected["nftables"]) {
		return 0, ErrObservation
	}
	return remaining, nil
}

func leaseGateNumber(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil && i >= 0
}

func leaseGateMetainfo(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) > 3 {
		return false
	}
	for key, value := range m {
		switch key {
		case "version", "release_name":
			s, ok := value.(string)
			if !ok || len(s) > 128 {
				return false
			}
		case "json_schema_version":
			n, ok := leaseGateNumber(value)
			if !ok || n != 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
