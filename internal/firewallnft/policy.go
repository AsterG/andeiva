// Package firewallnft compiles the isolated administrative IPv4 lab policy.
// It does not implement identity or mandatory application inspection.
package firewallnft

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftengine"
)

const (
	CompilerVersion = "andeiva.nft.admin.v2"
	TableName       = "andeiva_admin"
	MaxObservation  = 512 << 10
	// This mark belongs exclusively to this isolated gateway namespace. It
	// records prior admission, never authorization independent of current rules.
	AdmittedMark uint32 = 0x414e4445
)

var (
	ErrPolicy      = nftengine.ErrPolicy
	ErrObservation = nftengine.ErrObservation
)

type Artifact struct {
	Revision      configpoc.Revision
	Digest        string
	Batch, Create []byte
}
type object = map[string]any
type Engine = nftengine.Engine
type Transport = nftengine.Transport

func New(transport Transport) *Engine {
	return nftengine.New("nft-admin-v2", transport, func(c configpoc.Config) (nftengine.Artifact, error) {
		a, err := Compile(c)
		return nftengine.Artifact{Revision: a.Revision, Batch: a.Batch}, err
	}, DecodeObservation)
}

func DefaultConfig() configpoc.Config {
	return configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}}
}

func Compile(config configpoc.Config) (Artifact, error) {
	if config.SchemaVersion != 2 {
		return Artifact{}, ErrPolicy
	}
	revision, err := configpoc.Canonical(config)
	if err != nil {
		return Artifact{}, ErrPolicy
	}
	objects := policyObjects(revision)
	create := make([]object, 0, len(objects))
	for _, entry := range objects {
		create = append(create, object{"add": entry})
	}
	batch := append([]object{{"delete": object{"table": object{"family": "inet", "name": TableName}}}}, create...)
	createData, err := json.Marshal(object{"nftables": create})
	if err != nil {
		return Artifact{}, ErrPolicy
	}
	batchData, err := json.Marshal(object{"nftables": batch})
	if err != nil {
		return Artifact{}, ErrPolicy
	}
	sum := sha256.Sum256(batchData)
	return Artifact{Revision: revision, Digest: hex.EncodeToString(sum[:]), Batch: batchData, Create: createData}, nil
}

func match(left, right any) object {
	return object{"match": object{"op": "==", "left": left, "right": right}}
}
func ct(key string) object { return object{"ct": object{"key": key}} }
func state(value any) object {
	return object{"match": object{"op": "in", "left": ct("state"), "right": value}}
}
func payload(protocol, field string) object {
	return object{"payload": object{"protocol": protocol, "field": field}}
}
func address(cidr string) any {
	p := netip.MustParsePrefix(cidr)
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return object{"prefix": object{"addr": p.Addr().String(), "len": p.Bits()}}
}
func ports(p configpoc.PortRange) any {
	if p.From == p.To {
		return p.From
	}
	return object{"range": []uint16{p.From, p.To}}
}

func policyObjects(revision configpoc.Revision) []object {
	objects := []object{
		{"table": object{"family": "inet", "name": TableName, "comment": CompilerVersion + ":" + revision.Hash}},
		{"chain": object{"family": "inet", "table": TableName, "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
	}
	for _, rule := range revision.Config.Rules {
		m := rule.Match
		for _, reverse := range []bool{false, true} {
			input, output, source, destination, sourcePorts, destinationPorts, direction := "src0", "dst0", m.Source, m.Destination, m.SourcePorts, m.DestinationPorts, "f"
			if reverse {
				input, output, source, destination, sourcePorts, destinationPorts, direction = output, input, destination, source, destinationPorts, sourcePorts, "r"
			}
			expressions := []object{
				match(object{"meta": object{"key": "nfproto"}}, "ipv4"),
				match(object{"meta": object{"key": "iifname"}}, input),
				match(object{"meta": object{"key": "oifname"}}, output),
				match(payload("ip", "saddr"), address(source)),
				match(payload("ip", "daddr"), address(destination)),
				match(object{"meta": object{"key": "l4proto"}}, m.Protocol),
				match(payload(m.Protocol, "sport"), ports(sourcePorts)),
				match(payload(m.Protocol, "dport"), ports(destinationPorts)),
			}
			verdict := "drop"
			if rule.Action == "allow" {
				verdict = "accept"
				if reverse {
					expressions = append(expressions, match(ct("direction"), "reply"), state("established"), match(ct("mark"), AdmittedMark))
				} else {
					// Reevaluate every original packet, including established flows.
					// Invalid/untracked packets cannot acquire an admission mark.
					expressions = append(expressions, match(ct("direction"), "original"), state([]string{"established", "new"}), object{"mangle": object{"key": ct("mark"), "value": AdmittedMark}})
				}
			}
			expressions = append(expressions, object{"counter": object{"packets": 0, "bytes": 0}}, object{verdict: nil})
			objects = append(objects, object{"rule": object{"family": "inet", "table": TableName, "chain": "forward", "expr": expressions, "comment": fmt.Sprintf("%s:%s:%s", CompilerVersion, rule.ID, direction)}})
		}
	}
	return objects
}
