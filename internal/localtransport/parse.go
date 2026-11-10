package localtransport

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/nftengine"
)

type object = map[string]any

func objects(data []byte, limit int) ([]object, error) {
	if len(data) == 0 || len(data) > limit || !nftengine.UniqueJSONFields(data) {
		return nil, ErrInput
	}
	var envelope struct {
		NFTables []object `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.NFTables == nil {
		return nil, ErrInput
	}
	return envelope.NFTables, nil
}
func equal(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
func hash(text any, prefix string) bool {
	s, ok := text.(string)
	if !ok || !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	h := strings.TrimPrefix(s, prefix)
	b, e := hex.DecodeString(h)
	return e == nil && hex.EncodeToString(b) == h
}
func uintValue(value any, bits int) (uint64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	v, e := strconv.ParseUint(n.String(), 10, bits)
	return v, e == nil
}
func named(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func validateBatch(data []byte) error {
	commands, err := objects(data, localnft.MaxBatch)
	if err != nil || len(commands) < 2 || len(commands) > localnft.MaxRules+localnft.MaxControlRules+3 {
		return ErrInput
	}
	if _, exists := commands[0]["delete"]; exists {
		if !equal(commands[0], object{"delete": object{"table": object{"family": "inet", "name": localnft.TableName}}}) {
			return ErrInput
		}
		commands = commands[1:]
	}
	if len(commands) < 2 {
		return ErrInput
	}
	table, ok := addBody(commands[0], "table")
	if !ok || len(table) != 3 || table["family"] != "inet" || table["name"] != localnft.TableName || !hash(table["comment"], localnft.CompilerVersion+":") {
		return ErrInput
	}
	chain, ok := addBody(commands[1], "chain")
	if !ok || !equal(chain, object{"family": "inet", "table": localnft.TableName, "name": "input", "type": "filter", "hook": "input", "prio": 10, "policy": "drop"}) {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, command := range commands[2:] {
		r, ok := addBody(command, "rule")
		if !ok || len(r) != 5 || r["family"] != "inet" || r["table"] != localnft.TableName || r["chain"] != "input" {
			return ErrInput
		}
		comment, ok := r["comment"].(string)
		if !ok || seen[comment] {
			return ErrInput
		}
		seen[comment] = true
		expr, ok := r["expr"].([]any)
		if !ok || !validExpressions(expr, comment) {
			return ErrInput
		}
	}
	return nil
}
func addBody(command object, kind string) (object, bool) {
	if len(command) != 1 {
		return nil, false
	}
	add, ok := command["add"].(object)
	if !ok || len(add) != 1 {
		return nil, false
	}
	body, ok := add[kind].(object)
	return body, ok
}
func right(raw any, left object) (any, bool) {
	expr, ok := raw.(object)
	if !ok || len(expr) != 1 {
		return nil, false
	}
	m, ok := expr["match"].(object)
	if !ok || len(m) != 3 || m["op"] != "==" || !equal(m["left"], left) {
		return nil, false
	}
	v, ok := m["right"]
	return v, ok
}
func meta(key string) object { return object{"meta": object{"key": key}} }
func payload(proto, field string) object {
	return object{"payload": object{"protocol": proto, "field": field}}
}
func address(value any, ipv6, unspecified, multicast bool) (netip.Addr, bool) {
	text, ok := value.(string)
	if !ok {
		return netip.Addr{}, false
	}
	a, e := netip.ParseAddr(text)
	return a, e == nil && a.String() == text && a.Zone() == "" && !a.Is4In6() && a.Is6() == ipv6 && (!a.IsUnspecified() || unspecified) && (!a.IsMulticast() || multicast)
}
func source(value any, ipv6 bool) bool {
	if _, ok := address(value, ipv6, false, false); ok {
		return true
	}
	v, ok := value.(object)
	if !ok || len(v) != 1 {
		return false
	}
	p, ok := v["prefix"].(object)
	if !ok || len(p) != 2 {
		return false
	}
	a, ok := address(p["addr"], ipv6, false, false)
	if !ok {
		return false
	}
	valueBits, ok := p["len"].(json.Number)
	if !ok {
		return false
	}
	bits, err := strconv.Atoi(valueBits.String())
	if err != nil || bits <= 0 || bits > a.BitLen() {
		return false
	}
	prefix := netip.PrefixFrom(a, bits)
	return prefix == prefix.Masked()
}
func port(value any) bool {
	if p, ok := uintValue(value, 16); ok {
		return p > 0
	}
	v, ok := value.(object)
	if !ok || len(v) != 1 {
		return false
	}
	r, ok := v["range"].([]any)
	if !ok || len(r) != 2 {
		return false
	}
	lo, lok := uintValue(r[0], 16)
	hi, hok := uintValue(r[1], 16)
	return lok && hok && lo > 0 && lo < hi
}
func validExpressions(expr []any, comment string) bool {
	if len(expr) != 8 && len(expr) != 11 {
		return false
	}
	n := len(expr)
	if !equal(expr[n-2], object{"counter": nil}) || !equal(expr[n-1], object{"accept": nil}) {
		return false
	}
	family, ok := right(expr[0], meta("nfproto"))
	if !ok || (family != "ipv4" && family != "ipv6") {
		return false
	}
	i, ok := right(expr[1], meta("iifname"))
	iface, isString := i.(string)
	if !ok || !isString || !named(iface) || len(iface) > 15 {
		return false
	}
	if len(expr) == 8 {
		if !hash(comment, "andeiva-local:") {
			return false
		}
		ip := "ip"
		ipv6 := family == "ipv6"
		if ipv6 {
			ip = "ip6"
		}
		dst, ok := right(expr[2], payload(ip, "daddr"))
		if !ok {
			return false
		}
		if _, ok := address(dst, ipv6, false, false); !ok {
			return false
		}
		src, ok := right(expr[3], payload(ip, "saddr"))
		if !ok || !source(src, ipv6) {
			return false
		}
		protocol, ok := right(expr[4], meta("l4proto"))
		if !ok || (protocol != "tcp" && protocol != "udp") {
			return false
		}
		ports, ok := right(expr[5], payload(protocol.(string), "dport"))
		return ok && port(ports)
	}
	if family != "ipv6" || !hash(comment, "andeiva-nd:") {
		return false
	}
	sv, ok := right(expr[2], payload("ip6", "saddr"))
	if !ok {
		return false
	}
	src, ok := address(sv, true, true, false)
	if !ok {
		return false
	}
	dv, ok := right(expr[3], payload("ip6", "daddr"))
	if !ok {
		return false
	}
	dst, ok := address(dv, true, false, true)
	if !ok {
		return false
	}
	hop, ok := right(expr[4], payload("ip6", "hoplimit"))
	if !ok || hop != json.Number("255") {
		return false
	}
	proto, ok := right(expr[5], meta("l4proto"))
	if !ok || proto != "ipv6-icmp" {
		return false
	}
	kind, ok := right(expr[6], payload("icmpv6", "type"))
	if !ok || (kind != json.Number("135") && kind != json.Number("136")) {
		return false
	}
	code, ok := right(expr[7], payload("icmpv6", "code"))
	if !ok || code != json.Number("0") {
		return false
	}
	tv, ok := right(expr[8], payload("icmpv6", "taddr"))
	if !ok {
		return false
	}
	target, ok := address(tv, true, false, false)
	if !ok {
		return false
	}
	if kind == json.Number("136") {
		return src == target && (!dst.IsMulticast() || dst.String() == "ff02::1")
	}
	b := target.As16()
	m := netip.MustParseAddr("ff02::1:ff00:0").As16()
	copy(m[13:], b[13:])
	solicited := netip.AddrFrom16(m)
	return (dst == target || dst == solicited) && (!src.IsUnspecified() || dst == solicited)
}

func tableExists(data []byte) (bool, error) {
	entries, err := objects(data, MaxOutput)
	if err != nil || len(entries) > maxTables+1 {
		return false, ErrObservation
	}
	seen := map[string]bool{}
	found := false
	for index, entry := range entries {
		if len(entry) != 1 {
			return false, ErrObservation
		}
		if m, ok := entry["metainfo"]; ok {
			if index != 0 || !nftengine.ValidMetainfo(m) {
				return false, ErrObservation
			}
			continue
		}
		t, ok := entry["table"].(object)
		if !ok || len(t) < 2 || len(t) > 4 {
			return false, ErrObservation
		}
		for k, v := range t {
			switch k {
			case "family", "name":
			case "handle":
				if _, ok := uintValue(v, 64); !ok {
					return false, ErrObservation
				}
			case "comment":
				s, ok := v.(string)
				if !ok || len(s) > 128 {
					return false, ErrObservation
				}
			default:
				return false, ErrObservation
			}
		}
		family, ok := t["family"].(string)
		if !ok || (family != "inet" && family != "ip" && family != "ip6" && family != "arp" && family != "bridge" && family != "netdev") {
			return false, ErrObservation
		}
		name, ok := t["name"].(string)
		if !ok || !named(name) {
			return false, ErrObservation
		}
		key := family + "/" + name
		if seen[key] {
			return false, ErrObservation
		}
		seen[key] = true
		if name == localnft.TableName {
			if family != "inet" {
				return false, ErrObservation
			}
			found = true
		}
	}
	return found, nil
}

// Detailed rule equivalence belongs to localnft.VerifyObservation. This boundary
// rejects any table listing that escapes the sole transport-owned table.
func validateListing(data []byte) error {
	entries, err := objects(data, MaxOutput)
	if err != nil || len(entries) < 2 || len(entries) > localnft.MaxRules+localnft.MaxControlRules+3 {
		return ErrObservation
	}
	seenTable := false
	seenChain := false
	seenRules := map[string]bool{}
	for index, entry := range entries {
		if len(entry) != 1 {
			return ErrObservation
		}
		if m, ok := entry["metainfo"]; ok {
			if index != 0 || !nftengine.ValidMetainfo(m) {
				return ErrObservation
			}
			continue
		}
		for kind, raw := range entry {
			body, ok := raw.(object)
			if !ok || body["family"] != "inet" {
				return ErrObservation
			}
			if handle, exists := body["handle"]; exists {
				if _, ok := uintValue(handle, 64); !ok {
					return ErrObservation
				}
				delete(body, "handle")
			}
			switch kind {
			case "table":
				if seenTable || len(body) != 3 || body["name"] != localnft.TableName || !hash(body["comment"], localnft.CompilerVersion+":") {
					return ErrObservation
				}
				seenTable = true
			case "chain":
				if !seenTable || seenChain || !equal(body, object{"family": "inet", "table": localnft.TableName, "name": "input", "type": "filter", "hook": "input", "prio": 10, "policy": "drop"}) {
					return ErrObservation
				}
				seenChain = true
			case "rule":
				if !seenTable || !seenChain || body["table"] != localnft.TableName {
					return ErrObservation
				}
				if len(body) != 5 || body["chain"] != "input" || (!hash(body["comment"], "andeiva-local:") && !hash(body["comment"], "andeiva-nd:")) {
					return ErrObservation
				}
				id := body["comment"].(string)
				if seenRules[id] {
					return ErrObservation
				}
				seenRules[id] = true
				if expr, ok := body["expr"].([]any); !ok || len(expr) < 6 || len(expr) > 11 {
					return ErrObservation
				}
			default:
				return ErrObservation
			}
		}
	}
	if !seenTable || !seenChain {
		return ErrObservation
	}
	return nil
}
