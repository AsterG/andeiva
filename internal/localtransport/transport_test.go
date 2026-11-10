package localtransport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func artifact(t *testing.T) localnft.Artifact {
	t.Helper()
	c := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1", "fd42:616e:6465:1::1"}}}, Services: []localpolicy.Service{{ID: "admin", Owner: "management", Kind: localpolicy.ManagementHTTPS, Enabled: true, CompatibleZones: []localpolicy.Zone{localpolicy.LAN}, Authentication: localpolicy.Authenticated, Endpoints: []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 8443, LastPort: 8443}}, Bindings: []localpolicy.Binding{{Interface: "src0", Zone: localpolicy.LAN, LocalAddress: "198.18.1.1", Sources: []string{"198.18.1.2/32"}}, {Interface: "src0", Zone: localpolicy.LAN, LocalAddress: "fd42:616e:6465:1::1", Sources: []string{"fd42:616e:6465:1::2/128"}}}, Lifecycle: localpolicy.Lifecycle{VerifyListeners: true, VerifyRules: true, RevertOnFailure: true, ConfirmedManagementChanges: true}}}}
	a, e := localnft.CompileWithNeighbors(c, []localnft.NeighborLink{{Interface: "src0", LocalAddresses: []string{"fd42:616e:6465:1::1"}, PeerAddresses: []string{"fd42:616e:6465:1::2"}}})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func listing(t *testing.T, a localnft.Artifact) []byte {
	t.Helper()
	commands, e := objects(a.Create, localnft.MaxBatch)
	if e != nil {
		t.Fatal(e)
	}
	out := []object{}
	for _, c := range commands {
		out = append(out, c["add"].(object))
	}
	return encode(t, object{"nftables": out})
}
func tables() []byte {
	return []byte(`{"nftables":[{"table":{"family":"inet","name":"andeiva_local"}}]}`)
}

func TestCompilerBatchesAndNarrowScope(t *testing.T) {
	a := artifact(t)
	for _, batch := range [][]byte{a.Create, a.Batch} {
		if e := validateBatch(batch); e != nil {
			t.Fatal("compiler mismatch", e)
		}
	}
	cases := map[string]func([]object) []object{
		"foreign_table":     func(c []object) []object { c[0]["add"].(object)["table"].(object)["name"] = "filter"; return c },
		"hook_forward":      func(c []object) []object { c[1]["add"].(object)["chain"].(object)["hook"] = "forward"; return c },
		"policy_accept":     func(c []object) []object { c[1]["add"].(object)["chain"].(object)["policy"] = "accept"; return c },
		"unknown_operation": func(c []object) []object { return append(c, object{"flush": object{"ruleset": nil}}) },
		"unknown_expr": func(c []object) []object {
			r := c[len(c)-1]["add"].(object)["rule"].(object)
			r["expr"].([]any)[0] = object{"jump": object{"target": "forward"}}
			return c
		},
		"unknown_rule_field": func(c []object) []object { c[len(c)-1]["add"].(object)["rule"].(object)["position"] = 1; return c },
		"duplicate_rule":     func(c []object) []object { return append(c, c[len(c)-1]) },
		"source_any": func(c []object) []object {
			r := c[len(c)-1]["add"].(object)["rule"].(object)
			r["expr"].([]any)[3].(object)["match"].(object)["right"] = object{"prefix": object{"addr": "::", "len": 0}}
			return c
		},
		"invalid_port": func(c []object) []object {
			r := c[len(c)-1]["add"].(object)["rule"].(object)
			r["expr"].([]any)[5].(object)["match"].(object)["right"] = 0
			return c
		},
		"invalid_hop": func(c []object) []object {
			r := c[2]["add"].(object)["rule"].(object)
			r["expr"].([]any)[4].(object)["match"].(object)["right"] = 64
			return c
		},
		"icmp_redirect": func(c []object) []object {
			r := c[2]["add"].(object)["rule"].(object)
			r["expr"].([]any)[6].(object)["match"].(object)["right"] = 137
			return c
		},
		"icmp_bad_target": func(c []object) []object {
			r := c[2]["add"].(object)["rule"].(object)
			r["expr"].([]any)[8].(object)["match"].(object)["right"] = "fd42::99"
			return c
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := objects(a.Create, localnft.MaxBatch)
			if validateBatch(encode(t, object{"nftables": change(c)})) == nil {
				t.Fatal("accepted unsafe batch")
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("flush ruleset\n"), []byte(`{"nftables":[],"nftables":[]}`), []byte(strings.Repeat("x", localnft.MaxBatch+1))} {
		if validateBatch(bad) == nil {
			t.Fatal("invalid input accepted")
		}
	}
}

func TestAbsenceNeedsSuccessfulStrictTableListing(t *testing.T) {
	for _, data := range []string{`{"nftables":[]}`, `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"andeiva_sentinel","handle":2}}]}`} {
		found, e := tableExists([]byte(data))
		if e != nil || found {
			t.Fatal(found, e)
		}
	}
	if found, e := tableExists(tables()); e != nil || !found {
		t.Fatal(found, e)
	}
	bad := []string{`{}`, `{"nftables":null}`, `{"nftables":[],"unknown":1}`, `{"nftables":[],"nftables":[]}`, `{"nftables":[{"table":{"family":"ip","name":"andeiva_local"}}]}`, `{"nftables":[{"table":{"family":"inet","name":"andeiva_local"}},{"table":{"family":"inet","name":"andeiva_local"}}]}`, `{"nftables":[{"table":{"family":"inet","name":"../host"}}]}`, `{"nftables":[{"table":{"family":"inet","name":"x","handle":-1}}]}`, `{"nftables":[{"chain":{"family":"inet","name":"input"}}]}`}
	for _, data := range bad {
		if _, e := tableExists([]byte(data)); e == nil {
			t.Fatal("invalid listing accepted", data)
		}
	}
}

func TestCheckApplyPermitFailureAndInputReplacement(t *testing.T) {
	a := artifact(t)
	ops := []operation{}
	fail := false
	tr := &Transport{guard: func() error { return nil }, execute: func(ctx context.Context, op operation, input []byte) ([]byte, error) {
		ops = append(ops, op)
		if fail {
			return nil, ErrCommand
		}
		if op == check || op == apply {
			if !equal(json.RawMessage(input), json.RawMessage(a.Create)) {
				t.Error("changed batch")
			}
		}
		return nil, nil
	}}
	if tr.Apply(context.Background(), a.Create) == nil {
		t.Fatal("unchecked apply")
	}
	if e := tr.Check(context.Background(), a.Create); e != nil {
		t.Fatal(e)
	}
	if tr.Apply(context.Background(), a.Batch) == nil {
		t.Fatal("different unchecked bytes")
	}
	if tr.Apply(context.Background(), a.Create) == nil {
		t.Fatal("consumed permit reused")
	}
	if e := tr.Check(context.Background(), a.Create); e != nil {
		t.Fatal(e)
	}
	if e := tr.Apply(context.Background(), a.Create); e != nil {
		t.Fatal(e)
	}
	if tr.Apply(context.Background(), a.Create) == nil {
		t.Fatal("successful permit reused")
	}
	fail = true
	if tr.Check(context.Background(), a.Create) == nil || tr.Apply(context.Background(), a.Create) == nil {
		t.Fatal("failed check authorized apply")
	}
	if len(ops) != 4 {
		t.Fatal("unexpected execution", ops)
	}
}

func TestObserveDoesNotInferAbsenceFromErrors(t *testing.T) {
	a := artifact(t)
	failure := false
	absent := false
	wrong := false
	calls := 0
	tr := &Transport{guard: func() error { return nil }, execute: func(ctx context.Context, op operation, input []byte) ([]byte, error) {
		calls++
		if failure {
			return nil, ErrCommand
		}
		if op == listTables {
			if absent {
				return []byte(`{"nftables":[]}`), nil
			}
			return tables(), nil
		}
		if op == listTable {
			if wrong {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"foreign"}},{"chain":{"family":"inet","table":"foreign"}}]}`), nil
			}
			return listing(t, a), nil
		}
		return nil, ErrCommand
	}}
	data, exists, e := tr.Observe(context.Background())
	if e != nil || !exists || len(data) == 0 || calls != 2 {
		t.Fatal(exists, e, calls)
	}
	absent = true
	calls = 0
	data, exists, e = tr.Observe(context.Background())
	if e != nil || exists || data != nil || calls != 1 {
		t.Fatal("absence", exists, e, calls)
	}
	failure = true
	if _, _, e = tr.Observe(context.Background()); e == nil {
		t.Fatal("failure interpreted as absence")
	}
	failure = false
	absent = false
	wrong = true
	if _, _, e = tr.Observe(context.Background()); e == nil {
		t.Fatal("foreign listing accepted")
	}
	tr.execute = func(context.Context, operation, []byte) ([]byte, error) { return tables(), nil }
	if _, _, e = tr.Observe(context.Background()); e == nil {
		t.Fatal("table-only output accepted")
	}
}

func TestGuardCancellationBoundsAndConcurrency(t *testing.T) {
	a := artifact(t)
	calls := 0
	tr := &Transport{guard: func() error { return ErrIdentity }, execute: func(context.Context, operation, []byte) ([]byte, error) { calls++; return nil, nil }}
	if tr.Check(context.Background(), a.Create) == nil || calls != 0 {
		t.Fatal("identity bypass")
	}
	tr.guard = func() error { return nil }
	tr.execute = func(ctx context.Context, _ operation, _ []byte) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > CommandTimeout {
			t.Error("unbounded context")
		}
		return make([]byte, MaxOutput+1), nil
	}
	if tr.Check(context.Background(), a.Create) == nil {
		t.Fatal("output bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := tr.Check(ctx, a.Create); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	tr.execute = func(ctx context.Context, _ operation, _ []byte) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e := tr.Check(ctx, a.Create); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	tr.execute = func(context.Context, operation, []byte) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, exists, e := tr.Observe(context.Background())
			if e != nil || exists {
				t.Error(exists, e)
			}
		})
	}
	wg.Wait()
}
