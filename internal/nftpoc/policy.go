// Package nftpoc implements a bounded IPv4 laboratory adapter, not an appliance firewall.
package nftpoc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const (
	CompilerVersion = "andeiva.nft.fixture.v1"
	CatalogDigest   = "b9e12b86503e34dd42d56d24c8f012965c72d64398aa57cf520f02fbf3bf19aa"
	TableName       = "andeiva_poc"
	SourceAddress   = "198.18.0.2"
	SinkAddress     = "198.18.0.6"
	MaxObservation  = 64 << 10
)

var (
	ErrPolicy      = errors.New("ANDEIVA_NFT_INVALID_POLICY")
	ErrObservation = errors.New("ANDEIVA_NFT_INVALID_OBSERVATION")
	ErrDrift       = errors.New("ANDEIVA_NFT_DRIFT")
	ErrTransport   = errors.New("ANDEIVA_NFT_TRANSPORT_FAILURE")
)

type selector struct {
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

var selectors = [...]selector{
	{"tcp.a", "tcp", 18080}, {"udp.a", "udp", 18080},
	{"tcp.b", "tcp", 18081}, {"udp.b", "udp", 18081},
	// The second identifier permits an explicit first-match ordering experiment.
	{"tcp.a.second", "tcp", 18080}, {"udp.a.second", "udp", 18080},
}

// catalogDigest binds selectors, fixed endpoints and compiler semantics. Tests
// enforce the immutable catalog digest; semantic changes require a new version.
func catalogDigest() string {
	data, _ := json.Marshal(struct {
		Version, Source, Sink, Input, Output string
		Selectors                            []selector
	}{CompilerVersion, SourceAddress, SinkAddress, "src0", "dst0", selectors[:]})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func RuleID(label string) (string, error) {
	for _, entry := range selectors {
		if entry.Label == label {
			return "nft1." + CatalogDigest[:32] + "." + label, nil
		}
	}
	return "", ErrPolicy
}

func lookup(id string) (selector, error) {
	for _, entry := range selectors {
		known, _ := RuleID(entry.Label)
		if id == known {
			return entry, nil
		}
	}
	return selector{}, ErrPolicy
}

func DefaultConfig() configpoc.Config {
	return configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{}}
}

// FixtureConfig selects explicit fixture services; omitted services remain denied.
func FixtureConfig(tcpA, udpA, tcpB, udpB bool) configpoc.Config {
	config := DefaultConfig()
	for i, allowed := range []bool{tcpA, udpA, tcpB, udpB} {
		if allowed {
			id, _ := RuleID(selectors[i].Label)
			config.Rules = append(config.Rules, configpoc.Rule{ID: id, Action: "allow"})
		}
	}
	return config
}

type Artifact struct {
	Revision      configpoc.Revision
	CatalogDigest string
	Digest        string
	Batch         []byte
	Create        []byte
}

type object = map[string]any

func Compile(config configpoc.Config) (Artifact, error) {
	revision, err := configpoc.Canonical(config)
	if err != nil || len(config.Rules) > len(selectors) {
		return Artifact{}, ErrPolicy
	}
	for _, rule := range config.Rules {
		if _, err := lookup(rule.ID); err != nil {
			return Artifact{}, err
		}
	}
	objects := policyObjects(revision)
	create := make([]object, 0, len(objects))
	for _, entry := range objects {
		create = append(create, object{"add": entry})
	}
	batch := append([]object{{"delete": object{"table": object{"family": "inet", "name": TableName}}}}, create...)
	createData, _ := json.Marshal(object{"nftables": create})
	batchData, _ := json.Marshal(object{"nftables": batch})
	sum := sha256.Sum256(batchData)
	return Artifact{revision, CatalogDigest, hex.EncodeToString(sum[:]), batchData, createData}, nil
}

func policyObjects(revision configpoc.Revision) []object {
	objects := []object{
		{"table": object{"family": "inet", "name": TableName, "comment": CompilerVersion + ":" + CatalogDigest}},
		{"chain": object{"family": "inet", "table": TableName, "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
	}
	for _, rule := range revision.Config.Rules {
		entry, _ := lookup(rule.ID)
		for _, reverse := range []bool{false, true} {
			input, output, source, sink, portField, direction := "src0", "dst0", SourceAddress, SinkAddress, "dport", "f"
			if reverse {
				input, output, source, sink, portField, direction = output, input, sink, source, "sport", "r"
			}
			verdict := "drop"
			if rule.Action == "allow" {
				verdict = "accept"
			}
			expressions := []object{
				match(object{"meta": object{"key": "nfproto"}}, "ipv4"),
				match(object{"meta": object{"key": "iifname"}}, input),
				match(object{"meta": object{"key": "oifname"}}, output),
				match(object{"payload": object{"protocol": "ip", "field": "saddr"}}, source),
				match(object{"payload": object{"protocol": "ip", "field": "daddr"}}, sink),
				match(object{"meta": object{"key": "l4proto"}}, entry.Protocol),
				match(object{"payload": object{"protocol": entry.Protocol, "field": portField}}, entry.Port),
				{verdict: nil},
			}
			objects = append(objects, object{"rule": object{"family": "inet", "table": TableName, "chain": "forward", "expr": expressions, "comment": fmt.Sprintf("%s:%s:%s", CompilerVersion, rule.ID, direction)}})
		}
	}
	return objects
}

func match(left, right any) object {
	return object{"match": object{"op": "==", "left": left, "right": right}}
}
