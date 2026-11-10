package nftpoc

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func observation(t *testing.T, config configpoc.Config) []byte {
	t.Helper()
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(object{"nftables": policyObjects(compiled.Revision)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCatalogCompilerAndReadback(t *testing.T) {
	if catalogDigest() != CatalogDigest {
		t.Fatal("catalog changed without updating its versioned identity")
	}
	for mask := 0; mask < 16; mask++ {
		config := FixtureConfig(mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0)
		first, err := Compile(config)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := Compile(config)
		if !bytes.Equal(first.Batch, second.Batch) || first.Digest != second.Digest || len(first.Digest) != 64 || first.CatalogDigest != CatalogDigest {
			t.Fatal("unstable artifact")
		}
		if bytes.Contains(first.Batch, []byte("flush")) || bytes.Count(first.Batch, []byte(`"delete"`)) != 1 || bytes.Contains(first.Create, []byte(`"delete"`)) {
			t.Fatal("unexpected mutation scope")
		}
		observed, err := DecodeObservation(observation(t, config))
		if err != nil || observed.Hash != first.Revision.Hash {
			t.Fatalf("roundtrip mask=%d: %v", mask, err)
		}
	}
	firstID, _ := RuleID("tcp.a")
	secondID, _ := RuleID("tcp.a.second")
	config := DefaultConfig()
	config.Rules = []configpoc.Rule{{ID: firstID, Action: "deny"}, {ID: secondID, Action: "allow"}}
	first, _ := Compile(config)
	config.Rules[0], config.Rules[1] = config.Rules[1], config.Rules[0]
	second, _ := Compile(config)
	if first.Revision.Hash == second.Revision.Hash || first.Digest == second.Digest {
		t.Fatal("rule order not bound")
	}
}

func TestCompilerRejectsUnboundedPolicies(t *testing.T) {
	id, _ := RuleID("tcp.a")
	for name, config := range map[string]configpoc.Config{
		"schema":    {SchemaVersion: 2, DefaultAction: "deny"},
		"default":   {SchemaVersion: 1, DefaultAction: "allow"},
		"unknown":   {SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "tcp.a", Action: "allow"}}},
		"injection": {SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "x; flush ruleset", Action: "allow"}}},
		"verdict":   {SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: id, Action: "accept"}}},
		"duplicate": {SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: id, Action: "allow"}, {ID: id, Action: "deny"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, err := RuleID("tcp.c"); err == nil {
		t.Fatal("unknown fixture label accepted")
	}
}

func TestObservationRejectsSemanticDrift(t *testing.T) {
	valid := observation(t, FixtureConfig(true, true, false, false))
	cases := map[string][]byte{
		"duplicate-field":  bytes.Replace(valid, []byte(`"prio":0`), []byte(`"prio":900,"prio":0`), 1),
		"trailing":         append(append([]byte{}, valid...), []byte(`{}`)...),
		"oversized":        bytes.Repeat([]byte(" "), MaxObservation+1),
		"table":            bytes.Replace(valid, []byte(`"andeiva_poc"`), []byte(`"foreign"`), 1),
		"hook":             bytes.Replace(valid, []byte(`"hook":"forward"`), []byte(`"hook":"input"`), 1),
		"default":          bytes.Replace(valid, []byte(`"policy":"drop"`), []byte(`"policy":"accept"`), 1),
		"source":           bytes.Replace(valid, []byte(SourceAddress), []byte("0.0.0.0"), 1),
		"port":             bytes.Replace(valid, []byte(`18080`), []byte(`22`), 1),
		"unknown":          bytes.Replace(valid, []byte(`"prio":0`), []byte(`"prio":0,"unknown":true`), 1),
		"extra-expression": bytes.Replace(valid, []byte(`{"accept":null}`), []byte(`{"counter":{}},{"accept":null}`), 1),
		"reverse-verdict":  bytes.Replace(valid, []byte(`"comment":"`+CompilerVersion+":"), []byte(`"comment":"unexpected:`), 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObservation(data); err == nil {
				t.Fatal("modified semantics accepted")
			}
		})
	}
	withHandles := bytes.ReplaceAll(valid, []byte(`"family":"inet"`), []byte(`"family":"inet","handle":42`))
	withHandles = bytes.Replace(withHandles, []byte(`"nftables":[`), []byte(`"nftables":[{"metainfo":{"version":"test","release_name":"test","json_schema_version":1}},`), 1)
	if _, err := DecodeObservation(withHandles); err != nil {
		t.Fatalf("known volatile fields rejected: %v", err)
	}
}

func TestObservationNft113ProtocolDependencyRendering(t *testing.T) {
	artifact, err := Compile(FixtureConfig(true, true, true, true))
	if err != nil {
		t.Fatal(err)
	}
	for mask := 0; mask < 4; mask++ {
		objects := policyObjects(artifact.Revision)
		for _, entry := range objects[2:] {
			rule := entry["rule"].(object)
			original := rule["expr"].([]object)
			var rendered []object
			for i, expression := range original {
				if (i == 0 && mask&1 != 0) || (i == 5 && mask&2 != 0) {
					continue
				}
				if i == 5 {
					protocol := 6
					if expression["match"].(object)["right"] == "udp" {
						protocol = 17
					}
					expression = match(object{"meta": object{"key": "l4proto"}}, protocol)
				}
				rendered = append(rendered, expression)
			}
			rule["expr"] = rendered
		}
		data, _ := json.Marshal(object{"nftables": objects})
		got, err := DecodeObservation(data)
		if err != nil || got.Hash != artifact.Revision.Hash {
			t.Fatalf("nft rendering mask=%d: %v", mask, err)
		}
		for name, changed := range map[string][]byte{
			"wrong-payload-family":    bytes.Replace(data, []byte(`"protocol":"ip"`), []byte(`"protocol":"ip6"`), 1),
			"wrong-payload-transport": bytes.Replace(data, []byte(`"protocol":"tcp"`), []byte(`"protocol":"udp"`), 1),
			"wrong-input":             bytes.Replace(data, []byte(`"right":"src0"`), []byte(`"right":"dst0"`), 1),
			"wrong-verdict":           bytes.Replace(data, []byte(`{"accept":null}`), []byte(`{"drop":null}`), 1),
		} {
			if _, err := DecodeObservation(changed); err == nil {
				t.Fatalf("mask=%d accepted %s", mask, name)
			}
		}
		// Even when protocol dependencies disappear, all five payload/interface
		// selectors and their ordering remain required in both directions.
		for index := range objects[2]["rule"].(object)["expr"].([]object) {
			var changed struct {
				Objects []object `json:"nftables"`
			}
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			rule := changed.Objects[2]["rule"].(map[string]any)
			exprs := rule["expr"].([]any)
			rule["expr"] = append(exprs[:index], exprs[index+1:]...)
			mutated, _ := json.Marshal(object{"nftables": changed.Objects})
			_, err := DecodeObservation(mutated)
			// Only nfproto and l4proto are allowed to be elided.
			removed := objects[2]["rule"].(object)["expr"].([]object)[index]
			dependency := equalJSON(removed, match(object{"meta": object{"key": "nfproto"}}, "ipv4")) || equalJSON(removed, match(object{"meta": object{"key": "l4proto"}}, 6))
			if (err == nil) != dependency {
				t.Fatalf("mask=%d selector deletion %d: %v", mask, index, err)
			}
		}
	}
}
