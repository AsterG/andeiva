package routednft

import (
	"encoding/json"
	"net/netip"
)

type object = map[string]any
type Artifact struct {
	Revision      Revision
	Create, Batch []byte
}

func match(left, right any) object {
	return object{"match": object{"op": "==", "left": left, "right": right}}
}
func meta(key string) object { return object{"meta": object{"key": key}} }
func ct(key string) object   { return object{"ct": object{"key": key}} }
func original(key string) object {
	body := object{"key": key, "dir": "original"}
	if key == "saddr" || key == "daddr" {
		// nft 1.1.3's JSON parser ignores the documented family member. Use
		// the explicit IPv4 token, whose datatype/width are unambiguous.
		body["key"] = "ip " + key
	}
	return object{"ct": body}
}

func originalProtocol(protocol string) object {
	value := 6
	if protocol == "udp" {
		value = 17
	}
	// The original connection protocol is an 8-bit value, independent of the
	// current packet's transport protocol (ICMP for related errors). An identity
	// mask keeps that distinction in nft's expression context without weakening
	// the exact original-protocol predicate.
	return match(object{"&": []any{original("protocol"), 255}}, value)
}
func address(value string) any {
	p := netip.MustParsePrefix(value)
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return object{"prefix": object{"addr": p.Addr().String(), "len": p.Bits()}}
}
func port(p Ports) any {
	if p.From == p.To {
		return p.From
	}
	return object{"range": []uint16{p.From, p.To}}
}
func counter() object { return object{"counter": object{"packets": 0, "bytes": 0}} }

func Compile(policy Policy) (Artifact, error) {
	r, e := Canonical(policy)
	if e != nil {
		return Artifact{}, e
	}
	objects := policyObjects(r)
	create := make([]object, 0, len(objects))
	for _, o := range objects {
		create = append(create, object{"add": o})
	}
	batch := append([]object{{"delete": object{"table": object{"family": "inet", "name": TableName}}}}, create...)
	a, _ := json.Marshal(object{"nftables": create})
	b, _ := json.Marshal(object{"nftables": batch})
	return Artifact{Revision: r, Create: a, Batch: b}, nil
}

func policyObjects(r Revision) []object {
	objects := []object{
		{"table": object{"family": "inet", "name": TableName, "comment": "andeiva.routed.v1:" + r.Hash}},
		{"chain": object{"family": "inet", "table": TableName, "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
		{"chain": object{"family": "inet", "table": TableName, "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
	}
	add := func(chain, comment string, expr []object) {
		objects = append(objects, object{"rule": object{"family": "inet", "table": TableName, "chain": chain, "expr": expr, "comment": comment}})
	}
	interfaces := map[string]string{}
	for _, i := range r.Policy.Network.Config.Interfaces {
		interfaces[i.ID] = i.Binding.Name
	}
	for _, rule := range r.Policy.Rules {
		if !rule.IsEnabled() {
			continue
		}
		for _, reply := range []bool{false, true} {
			in, out, dir := interfaces[rule.Path.FromInterface], interfaces[rule.Path.ToInterface], "original"
			if reply {
				in, out, dir = out, in, "reply"
			}
			// Conntrack's original tuple survives SNAT and the inverse translation on
			// replies. Packet source/destination addresses alone cannot prove this scope.
			common := []object{match(meta("nfproto"), "ipv4"), match(meta("iifname"), in), match(meta("oifname"), out), match(ct("direction"), dir), match(original("saddr"), address(rule.Source)), match(original("daddr"), address(rule.Destination)), originalProtocol(rule.Protocol), match(original("proto-src"), port(rule.SourcePorts)), match(original("proto-dst"), port(rule.DestinationPorts))}
			emit := func(suffix string, extra ...object) {
				expr := append([]object{}, common...)
				expr = append(expr, extra...)
				add("forward", rule.ID+":"+dir+":"+suffix, expr)
			}
			if rule.Action == "deny" {
				emit("deny", counter(), object{"drop": nil})
				continue
			}
			normal := []object{match(meta("l4proto"), rule.Protocol)}
			if reply {
				normal = append(normal, match(ct("state"), "established"), match(ct("mark"), ruleMark(rule)))
			} else {
				normal = append(normal, object{"match": object{"op": "in", "left": ct("state"), "right": []string{"new", "established"}}}, object{"mangle": object{"key": ct("mark"), "value": ruleMark(rule)}})
			}
			normal = append(normal, counter(), object{"accept": nil})
			emit("allow", normal...)
			// Only ICMP errors attached by conntrack to this admitted, currently
			// permitted tuple qualify. Echo, redirects and unrelated errors remain denied.
			emit("related", match(meta("l4proto"), "icmp"), match(ct("state"), "related"), match(ct("mark"), ruleMark(rule)), match(object{"payload": object{"protocol": "icmp", "field": "type"}}, object{"set": []int{3, 11, 12}}), counter(), object{"accept": nil})
			// A matching allow whose state/mark is invalid must not fall through to a
			// later allow; preserve first-match semantics in both directions.
			emit("unadmitted", counter(), object{"drop": nil})
		}
	}
	add("forward", "default-deny", []object{counter(), object{"drop": nil}})
	for _, n := range r.Policy.NAT {
		add("postrouting", n.ID+":masquerade", []object{match(meta("nfproto"), "ipv4"), match(meta("iifname"), interfaces[n.Path.FromInterface]), match(meta("oifname"), interfaces[n.Path.ToInterface]), match(object{"payload": object{"protocol": "ip", "field": "saddr"}}, address(n.Source)), counter(), object{"masquerade": nil}})
	}
	return objects
}
