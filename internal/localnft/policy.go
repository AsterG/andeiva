// Package localnft compiles bounded Local-In policies without executing commands.
package localnft

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

const (
	TableName            = "andeiva_local"
	CompilerVersion      = "andeiva.local.runtime.v1"
	MaxServices          = 2
	MaxInterfaces        = 2
	MaxBindings          = 4
	MaxSources           = 16
	MaxRules             = 128
	MaxNeighborAddresses = 4
	MaxControlRules      = 136
	MaxConfig            = 24 << 10
	MaxBatch             = 384 << 10
	MaxObservation       = 512 << 10
)

var (
	ErrPolicy      = errors.New("local_nft_policy_invalid")
	ErrObservation = errors.New("local_nft_observation_invalid")
)

type object = map[string]any

// NeighborLink is trusted executor inventory, never a service-editing parameter.
// Exact peers let denied service clients resolve neighbors without an L4 grant.
type NeighborLink = localpolicy.NeighborLink

type Artifact struct {
	Revision   localpolicy.Revision        `json:"revision"`
	Digest     string                      `json:"digest"`
	Create     []byte                      `json:"create"`
	Batch      []byte                      `json:"batch"`
	Rules      []localpolicy.EffectiveRule `json:"rules"`
	Neighbors  []NeighborLink              `json:"neighbors"`
	ControlIDs []string                    `json:"control_ids"`
}

// ValidateManaged limits deployed listeners to the two implemented engines.
// Compile also supports UDP fixtures; successful compilation does not enable a
// service engine or prove that a listener exists.
func ValidateManaged(c localpolicy.Config) error {
	if err := bounded(c); err != nil {
		return err
	}
	if _, err := localpolicy.Canonical(c); err != nil {
		return ErrPolicy
	}
	seen := map[localpolicy.Kind]bool{}
	for _, s := range c.Services {
		if (s.Kind != localpolicy.ManagementHTTPS && s.Kind != localpolicy.ManagementSSH) || seen[s.Kind] {
			return ErrPolicy
		}
		seen[s.Kind] = true
		e := s.Endpoints[0]
		if e.Protocol != localpolicy.TCP || e.FirstPort < 1024 || e.FirstPort != e.LastPort {
			return ErrPolicy
		}
		for _, b := range s.Bindings {
			if netip.MustParseAddr(b.LocalAddress).IsLinkLocalUnicast() {
				return ErrPolicy
			}
		}
	}
	return nil
}

func bounded(c localpolicy.Config) error {
	if len(c.Interfaces) > MaxInterfaces || len(c.Services) > MaxServices {
		return ErrPolicy
	}
	for _, i := range c.Interfaces {
		if len(i.Addresses) > MaxNeighborAddresses {
			return ErrPolicy
		}
	}
	for _, s := range c.Services {
		if len(s.Bindings) > MaxBindings || len(s.Endpoints) != 1 {
			return ErrPolicy
		}
		for _, b := range s.Bindings {
			if len(b.Sources) > MaxSources {
				return ErrPolicy
			}
		}
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > MaxConfig {
		return ErrPolicy
	}
	return nil
}

// Compile grants no neighbor discovery traffic without explicit trusted peers.
func Compile(c localpolicy.Config) (Artifact, error) { return CompileWithNeighbors(c, nil) }

func CompileWithNeighbors(c localpolicy.Config, neighbors []NeighborLink) (Artifact, error) {
	if err := bounded(c); err != nil {
		return Artifact{}, err
	}
	pure, err := localpolicy.Compile(c)
	if err != nil || len(pure.Rules) > MaxRules {
		return Artifact{}, ErrPolicy
	}
	links, err := canonicalNeighbors(pure.Revision.Config, neighbors)
	if err != nil {
		return Artifact{}, err
	}
	commands := []object{
		{"add": object{"table": object{"family": "inet", "name": TableName, "comment": CompilerVersion + ":" + pure.Revision.Hash}}},
		{"add": object{"chain": object{"family": "inet", "table": TableName, "name": "input", "type": "filter", "hook": "input", "prio": localpolicy.InputPriority, "policy": "drop"}}},
	}
	controls := neighborRules(pure.Revision.Config, links)
	if len(controls) > MaxControlRules {
		return Artifact{}, ErrPolicy
	}
	ids := make([]string, 0, len(controls))
	for _, r := range controls {
		ids = append(ids, r["comment"].(string))
		commands = append(commands, object{"add": object{"rule": r}})
	}
	for _, r := range pure.Rules {
		ip := "ip6"
		if r.Family == "ipv4" {
			ip = "ip"
		}
		p := netip.MustParsePrefix(r.Source)
		var source any = object{"prefix": object{"addr": p.Addr().String(), "len": p.Bits()}}
		if p.Bits() == p.Addr().BitLen() {
			source = p.Addr().String()
		}
		var port any = r.Endpoint.FirstPort
		if r.Endpoint.FirstPort != r.Endpoint.LastPort {
			port = object{"range": []uint16{r.Endpoint.FirstPort, r.Endpoint.LastPort}}
		}
		exprs := []object{match(meta("nfproto"), r.Family), match(meta("iifname"), r.Interface),
			match(payload(ip, "daddr"), r.LocalAddress), match(payload(ip, "saddr"), source),
			match(meta("l4proto"), string(r.Endpoint.Protocol)), match(payload(string(r.Endpoint.Protocol), "dport"), port),
			{"counter": nil}, {"accept": nil}}
		commands = append(commands, object{"add": object{"rule": rule("andeiva-local:"+r.ID, exprs)}})
	}
	create, err := json.Marshal(object{"nftables": commands})
	if err != nil || len(create) > MaxBatch {
		return Artifact{}, ErrPolicy
	}
	replace := append([]object{{"delete": object{"table": object{"family": "inet", "name": TableName}}}}, commands...)
	batch, err := json.Marshal(object{"nftables": replace})
	if err != nil || len(batch) > MaxBatch {
		return Artifact{}, ErrPolicy
	}
	digestData, err := json.Marshal(struct {
		Create    []byte         `json:"create"`
		Neighbors []NeighborLink `json:"neighbors"`
	}{create, links})
	if err != nil {
		return Artifact{}, ErrPolicy
	}
	return Artifact{Revision: pure.Revision, Digest: hash(digestData), Create: create, Batch: batch, Rules: pure.Rules, Neighbors: links, ControlIDs: ids}, nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func meta(key string) object  { return object{"meta": object{"key": key}} }
func payload(protocol, field string) object {
	return object{"payload": object{"protocol": protocol, "field": field}}
}
func match(left, right any) object {
	return object{"match": object{"op": "==", "left": left, "right": right}}
}
func rule(comment string, expr []object) object {
	return object{"family": "inet", "table": TableName, "chain": "input", "expr": expr, "comment": comment}
}

func canonicalNeighbors(c localpolicy.Config, links []NeighborLink) ([]NeighborLink, error) {
	result, err := localpolicy.CanonicalNeighborInventory(c, links)
	if err != nil {
		return nil, ErrPolicy
	}
	return result, nil
}

func addresses(values []string) ([]string, error) {
	result, err := localpolicy.CanonicalNeighborAddresses(values)
	if err != nil {
		return nil, ErrPolicy
	}
	return result, nil
}

func solicitedNode(text string) string {
	a := netip.MustParseAddr(text).As16()
	m := netip.MustParseAddr("ff02::1:ff00:0").As16()
	copy(m[13:], a[13:])
	return netip.AddrFrom16(m).String()
}

func neighborRules(c localpolicy.Config, links []NeighborLink) []object {
	active := map[string]bool{}
	for _, s := range c.Services {
		if s.Enabled {
			for _, b := range s.Bindings {
				if netip.MustParseAddr(b.LocalAddress).Is6() {
					active[b.Interface] = true
				}
			}
		}
	}
	rules := make([]object, 0)
	for _, link := range links {
		if !active[link.Interface] {
			continue
		}
		add := func(kind int, source, destination, target string) {
			exprs := []object{match(meta("nfproto"), "ipv6"), match(meta("iifname"), link.Interface),
				match(payload("ip6", "saddr"), source), match(payload("ip6", "daddr"), destination),
				match(payload("ip6", "hoplimit"), 255), match(meta("l4proto"), "ipv6-icmp"),
				match(payload("icmpv6", "type"), kind), match(payload("icmpv6", "code"), 0),
				match(payload("icmpv6", "taddr"), target), {"counter": nil}, {"accept": nil}}
			encoded, _ := json.Marshal(exprs)
			rules = append(rules, rule("andeiva-nd:"+hash(encoded), exprs))
		}
		for _, local := range link.LocalAddresses {
			add(135, "::", solicitedNode(local), local)
			for _, peer := range link.PeerAddresses {
				add(135, peer, local, local)
				add(135, peer, solicitedNode(local), local)
				add(136, peer, local, peer)
			}
		}
		for _, peer := range link.PeerAddresses {
			add(136, peer, "ff02::1", peer)
		}
	}
	return rules
}
