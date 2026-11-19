package routednft

import (
	"encoding/json"
	"net/netip"

	"github.com/AsterG/andeiva/internal/routedmodel"
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

const tcpInitialFlagsMask = 0x17 // FIN, SYN, RST and ACK

func tcpInitialFlags() object {
	return object{"&": []any{object{"payload": object{"protocol": "tcp", "field": "flags"}}, tcpInitialFlagsMask}}
}

func Compile(policy Policy) (Artifact, error) {
	r, err := Canonical(policy)
	if err != nil {
		return Artifact{}, err
	}
	return compileRevision(r, nil), nil
}

// CompileRetainedWANChange derives the mark reservation and atomic rules for
// unchanged network and NAT. The caller must select the reservation before
// applying the batch and authenticate the same reservation at readback.
func CompileRetainedWANChange(before, target Revision, previous routedmodel.AdmissionMarks, highWater uint32) (Artifact, routedmodel.AdmissionMarks, error) {
	prior, err := Canonical(before.Policy)
	if err != nil || prior.Hash != before.Hash {
		return Artifact{}, routedmodel.AdmissionMarks{}, ErrPolicy
	}
	next, err := Canonical(target.Policy)
	if err != nil || next.Hash != target.Hash ||
		prior.Policy.Network.Hash != next.Policy.Network.Hash || !equal(prior.Policy.NAT, next.Policy.NAT) {
		return Artifact{}, routedmodel.AdmissionMarks{}, ErrPolicy
	}
	marks, needsClosure, err := routedmodel.ReserveAdmissionMarks(previous.Boot, highWater, &previous, prior, next)
	if err != nil {
		return Artifact{}, routedmodel.AdmissionMarks{}, err
	}
	if needsClosure {
		return Artifact{}, routedmodel.AdmissionMarks{}, ErrPolicy
	}
	artifact, err := CompileMarkedPolicy(next, marks)
	return artifact, marks, err
}

// CompileMarkedPolicy compiles an authenticated selection, including startup
// and guarded rollback. Legacy marked entries cannot gain authority here.
func CompileMarkedPolicy(revision Revision, assigned routedmodel.AdmissionMarks) (Artifact, error) {
	marks, err := assigned.MarkIndex(revision)
	if err != nil {
		return Artifact{}, err
	}
	canonical, err := Canonical(revision.Policy)
	if err != nil {
		return Artifact{}, err
	}
	return compileRevision(canonical, marks), nil
}

func compileRevision(r Revision, marks map[string]uint32) Artifact {
	objects := compiledObjects(r, marks)
	create := make([]object, 0, len(objects))
	for _, o := range objects {
		create = append(create, object{"add": o})
	}
	batch := append([]object{{"delete": object{"table": object{"family": "inet", "name": TableName}}}}, create...)
	a, _ := json.Marshal(object{"nftables": create})
	b, _ := json.Marshal(object{"nftables": batch})
	return Artifact{Revision: r, Create: a, Batch: b}
}

func compiledObjects(r Revision, marks map[string]uint32) []object {
	retainedWAN := marks != nil
	comment := "andeiva.routed.v1:"
	if retainedWAN {
		comment = "andeiva.routed.retained-wan.v1:"
	}
	drop := object{"drop": nil}
	objects := []object{
		{"table": object{"family": "inet", "name": TableName, "comment": comment + r.Hash}},
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
		mark := ruleMark(rule)
		if retainedWAN {
			mark = marks[rule.ID]
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
				emit("deny", counter(), drop)
				continue
			}
			normal := []object{match(meta("l4proto"), rule.Protocol)}
			if retainedWAN && !reply {
				admit := []object{match(meta("l4proto"), rule.Protocol), match(ct("state"), "new")}
				if rule.Protocol == "tcp" {
					// Loose TCP tracking can see midstream traffic as new after
					// expiry. Only a fresh SYN can gain an admission mark.
					admit = append(admit, match(tcpInitialFlags(), 0x02))
				}
				// Retransmits with the current mark still pass. An old mark
				// cannot change identity between the helper's dump and delete.
				emit("new-admitted", append(append([]object{}, admit...), match(ct("mark"), mark),
					counter(), object{"accept": nil})...)
				emit("new", append(admit, match(ct("mark"), 0), object{"mangle": object{"key": ct("mark"), "value": mark}},
					counter(), object{"accept": nil})...)
			}
			if reply || retainedWAN {
				normal = append(normal, match(ct("state"), "established"), match(ct("mark"), mark))
			} else {
				normal = append(normal, object{"match": object{"op": "in", "left": ct("state"), "right": []string{"new", "established"}}}, object{"mangle": object{"key": ct("mark"), "value": mark}})
			}
			normal = append(normal, counter(), object{"accept": nil})
			emit("allow", normal...)
			// Only ICMP errors attached by conntrack to this admitted, currently
			// permitted tuple qualify. Echo, redirects and unrelated errors remain denied.
			emit("related", match(meta("l4proto"), "icmp"), match(ct("state"), "related"), match(ct("mark"), mark), match(object{"payload": object{"protocol": "icmp", "field": "type"}}, object{"set": []int{3, 11, 12}}), counter(), object{"accept": nil})
			// A matching allow whose state/mark is invalid must not fall through to a
			// later allow; preserve first-match semantics in both directions.
			emit("unadmitted", counter(), drop)
		}
	}
	add("forward", "default-deny", []object{counter(), drop})
	for _, n := range r.Policy.NAT {
		add("postrouting", n.ID+":masquerade", []object{match(meta("nfproto"), "ipv4"), match(meta("iifname"), interfaces[n.Path.FromInterface]), match(meta("oifname"), interfaces[n.Path.ToInterface]), match(object{"payload": object{"protocol": "ip", "field": "saddr"}}, address(n.Source)), counter(), object{"masquerade": nil}})
	}
	return objects
}
