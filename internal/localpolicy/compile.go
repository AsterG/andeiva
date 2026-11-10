package localpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
)

type object = map[string]any

// Compile creates a new-table batch for an isolated namespace only. It cannot
// apply, flush or replace the host ruleset. nft --check and kernel readback are
// mandatory gates for a future adapter; successful compilation is not admission.
func Compile(c Config) (Artifact, error) {
	revision, err := Canonical(c)
	if err != nil {
		return Artifact{}, err
	}
	rules := make([]EffectiveRule, 0)
	for _, s := range revision.Config.Services {
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			for _, e := range s.Endpoints {
				for _, source := range b.Sources {
					family := "ipv6"
					if netip.MustParseAddr(b.LocalAddress).Is4() {
						family = "ipv4"
					}
					r := EffectiveRule{Owner: s.Owner, Service: s.ID, Management: management(s.Kind), Interface: b.Interface, Zone: b.Zone,
						Family: family, LocalAddress: b.LocalAddress, Source: source, Endpoint: e, Action: "allow", Origin: "local_service"}
					data, err := json.Marshal(r)
					if err != nil {
						return Artifact{}, invalid("rule_encoding")
					}
					sum := sha256.Sum256(data)
					r.ID = hex.EncodeToString(sum[:])
					r.Revision = revision.Hash
					rules = append(rules, r)
				}
			}
		}
	}
	commands := []object{
		{"add": object{"table": object{"family": "inet", "name": TableName, "comment": CompilerVersion + ":" + revision.Hash}}},
		{"add": object{"chain": object{"family": "inet", "table": TableName, "name": "input", "type": "filter", "hook": "input", "prio": InputPriority, "policy": "drop"}}},
	}
	for _, r := range rules {
		ip := "ip6"
		if r.Family == "ipv4" {
			ip = "ip"
		}
		prefix := netip.MustParsePrefix(r.Source)
		var ports any = r.Endpoint.FirstPort
		if r.Endpoint.FirstPort != r.Endpoint.LastPort {
			ports = object{"range": []uint16{r.Endpoint.FirstPort, r.Endpoint.LastPort}}
		}
		expressions := []object{
			match(object{"meta": object{"key": "nfproto"}}, r.Family),
			match(object{"meta": object{"key": "iifname"}}, r.Interface),
			match(object{"payload": object{"protocol": ip, "field": "daddr"}}, r.LocalAddress),
			match(object{"payload": object{"protocol": ip, "field": "saddr"}}, object{"prefix": object{"addr": prefix.Addr().String(), "len": prefix.Bits()}}),
			match(object{"meta": object{"key": "l4proto"}}, string(r.Endpoint.Protocol)),
			match(object{"payload": object{"protocol": string(r.Endpoint.Protocol), "field": "dport"}}, ports),
			{"counter": nil}, {"accept": nil},
		}
		commands = append(commands, object{"add": object{"rule": object{"family": "inet", "table": TableName, "chain": "input", "expr": expressions, "comment": "andeiva-local:" + r.ID}}})
	}
	data, err := json.Marshal(object{"nftables": commands})
	if err != nil {
		return Artifact{}, invalid("batch_encoding")
	}
	sum := sha256.Sum256(data)
	return Artifact{Revision: revision, Rules: rules, Digest: hex.EncodeToString(sum[:]), Create: data}, nil
}

func match(left, right any) object {
	return object{"match": object{"op": "==", "left": left, "right": right}}
}

type Impact struct {
	Before            string          `json:"before"`
	After             string          `json:"after"`
	Added             []EffectiveRule `json:"added"`
	Removed           []EffectiveRule `json:"removed"`
	RequiresConfirmed bool            `json:"requires_confirmed"`
}

// Preview compares derived permissions. Management changes require a future
// confirmed transaction and an independent post-change connectivity proof.
func Preview(before, after Config) (Impact, error) {
	a, err := Compile(before)
	if err != nil {
		return Impact{}, err
	}
	b, err := Compile(after)
	if err != nil {
		return Impact{}, err
	}
	result := Impact{Before: a.Revision.Hash, After: b.Revision.Hash, Added: []EffectiveRule{}, Removed: []EffectiveRule{}}
	// Dependency and lifecycle changes can affect administrative availability
	// even when the generated packet permissions are unchanged.
	managementDeclarations := func(c Config) ([]byte, error) {
		byID := make(map[string]Service, len(c.Services))
		for _, s := range c.Services {
			byID[s.ID] = s
		}
		included := make(map[string]bool)
		var include func(string)
		include = func(id string) {
			if included[id] {
				return
			}
			included[id] = true
			for _, dependency := range byID[id].DependsOn {
				include(dependency)
			}
		}
		for _, s := range c.Services {
			if management(s.Kind) {
				include(s.ID)
			}
		}
		services := make([]Service, 0)
		for _, s := range c.Services {
			if included[s.ID] {
				services = append(services, s)
			}
		}
		return json.Marshal(services)
	}
	oldManagement, err := managementDeclarations(a.Revision.Config)
	if err != nil {
		return Impact{}, invalid("management_encoding")
	}
	newManagement, err := managementDeclarations(b.Revision.Config)
	if err != nil {
		return Impact{}, invalid("management_encoding")
	}
	result.RequiresConfirmed = !bytes.Equal(oldManagement, newManagement)
	oldIDs, newIDs := map[string]bool{}, map[string]bool{}
	for _, r := range a.Rules {
		oldIDs[r.ID] = true
	}
	for _, r := range b.Rules {
		newIDs[r.ID] = true
		if !oldIDs[r.ID] {
			result.Added = append(result.Added, r)
			result.RequiresConfirmed = result.RequiresConfirmed || r.Management
		}
	}
	for _, r := range a.Rules {
		if !newIDs[r.ID] {
			result.Removed = append(result.Removed, r)
			result.RequiresConfirmed = result.RequiresConfirmed || r.Management
		}
	}
	return result, nil
}

// EffectiveView returns independently allocated records. Callers must obtain
// them by compilation; editing these records cannot change service declarations.
func EffectiveView(c Config, service string) ([]EffectiveRule, error) {
	a, err := Compile(c)
	if err != nil {
		return nil, err
	}
	if service == "" {
		return a.Rules, nil
	}
	return slices.DeleteFunc(a.Rules, func(r EffectiveRule) bool { return r.Service != service }), nil
}
