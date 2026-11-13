package networkexecutor

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type gateAuthorityFake struct {
	grant       LeaseGateGrant
	verify      func() error
	unavailable bool
}

func (a *gateAuthorityFake) Current(context.Context) (LeaseGateGrant, error) {
	if a.unavailable {
		return LeaseGateGrant{}, ErrLeaseUnavailable
	}
	return a.grant, nil
}
func (a *gateAuthorityFake) Verify(context.Context, LeaseGateGrant) error {
	if a.verify != nil {
		return a.verify()
	}
	return nil
}

type gateKernelFake struct {
	wan                    string
	now                    *int64
	objects                []any
	enabled                bool
	token                  map[string]any
	installed              int64
	applies, stages, opens int
	loseACK, failClose     bool
	afterApply             func()
	observe                func([]byte) []byte
}

func (k *gateKernelFake) Check(context.Context, []byte) error { return nil }
func (k *gateKernelFake) Apply(_ context.Context, b []byte) error {
	k.applies++
	var root struct {
		NFT []map[string]map[string]map[string]any `json:"nftables"`
	}
	if json.Unmarshal(b, &root) != nil {
		return ErrCommand
	}
	for _, cmd := range root.NFT {
		for verb, object := range cmd {
			if verb == "create" {
				if k.objects != nil {
					return ErrCommand
				}
				k.objects = leaseGateObjects(k.wan)
			}
			if verb == "flush" {
				if k.failClose {
					return ErrCommand
				}
				if object["set"]["name"] == "enabled" {
					k.enabled = false
				} else {
					k.token = nil
				}
			}
			if e, ok := object["element"]; ok {
				if e["name"] == "enabled" {
					k.enabled = true
					k.opens++
				} else {
					k.token = e["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
					k.installed = *k.now
					k.stages++
				}
			}
		}
	}
	if k.afterApply != nil {
		k.afterApply()
	}
	if k.loseACK {
		return ErrCommand
	}
	return nil
}
func (k *gateKernelFake) Observe(context.Context) ([]byte, error) {
	if k.objects == nil {
		return nil, ErrObservation
	}
	objects := leaseGateObjects(k.wan)
	if k.enabled {
		objects[1].(map[string]any)["set"].(map[string]any)["elem"] = []any{k.wan}
	}
	if k.token != nil {
		e := map[string]any{}
		for key, v := range k.token {
			e[key] = v
		}
		remaining := int64(e["timeout"].(float64)) - (*k.now-k.installed)/int64(time.Second)
		if remaining > 0 {
			e["expires"] = remaining
			objects[2].(map[string]any)["set"].(map[string]any)["elem"] = []any{map[string]any{"elem": e}}
		}
	}
	b := leaseGateEncode(objects)
	if k.observe != nil {
		b = k.observe(b)
	}
	return b, nil
}

func gateFixture(t *testing.T) (*LeaseGate, *gateKernelFake, *gateAuthorityFake, *int64) {
	t.Helper()
	e, _, opts, f, now := leaseInputs(t)
	a := &gateAuthorityFake{grant: LeaseGateGrant{Fact: *f, WorkHash: strings.Repeat("c", 64)}}
	k := &gateKernelFake{wan: f.WAN.Name, now: now}
	g, err := newLeaseGate(context.Background(), *e.identity, LeaseGateOptions{Desired: opts.Desired, Owner: opts.Owner, Authority: a}, k, func() (int64, error) { return *now, nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if k.applies != 0 {
		t.Fatal("constructor mutated kernel")
	}
	if err := g.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return g, k, a, now
}

func TestLeaseGateOpenDoesNotRecreateOrExtendToken(t *testing.T) {
	g, k, _, now := gateFixture(t)
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	installed, timeout := k.installed, k.token["timeout"]
	*now += 10 * int64(time.Second)
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !k.enabled || k.stages != 1 || k.opens != 1 || k.installed != installed || k.token["timeout"] != timeout {
		t.Fatal("open recreated token")
	}
	if err := g.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.enabled || k.token != nil {
		t.Fatal("close left authority")
	}
	if err := g.Stage(context.Background()); err == nil || k.stages != 1 {
		t.Fatal("same sequence recreated after close")
	}
}

func TestLeaseGateRenewRequiresCloseAndFreshSequence(t *testing.T) {
	g, k, a, _ := gateFixture(t)
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.grant.Fact.Sequence++
	if err := g.Stage(context.Background()); err == nil {
		t.Fatal("stage while open")
	}
	if err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.stages != 2 {
		t.Fatal(k.stages)
	}
}

func TestLeaseGateDelayedApplyReadbackCannotExtendDeadline(t *testing.T) {
	g, k, _, now := gateFixture(t)
	k.afterApply = func() {
		if k.stages == 1 {
			*now += 3 * int64(time.Second)
			k.installed = *now
		}
	}
	if err := g.Stage(context.Background()); err == nil {
		t.Fatal("late insertion extended original deadline")
	}
	if k.enabled || k.token != nil || !g.fenced {
		t.Fatal("failure not closed")
	}
}

func TestLeaseGateReadbackReceiptTimeIncludesTransportDelay(t *testing.T) {
	g, k, _, now := gateFixture(t)
	k.observe = func(b []byte) []byte {
		if k.token != nil {
			*now += 3 * int64(time.Second)
		}
		return b
	}
	if err := g.Stage(context.Background()); err == nil {
		t.Fatal("pre-receipt clock admitted delayed readback")
	}
	if k.enabled || k.token != nil {
		t.Fatal("not closed")
	}
}

func TestLeaseGateLostACKReadbackWithoutReplay(t *testing.T) {
	g, k, _, _ := gateFixture(t)
	k.loseACK = true
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.stages != 1 || k.opens != 1 {
		t.Fatal("replayed mutation")
	}
	if err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseGateRejectsAuthorityChangeAtFinalOpenReadback(t *testing.T) {
	for _, change := range []string{"revoke", "owner", "sequence", "deadline", "work", "unavailable", "expired"} {
		t.Run(change, func(t *testing.T) {
			g, k, a, now := gateFixture(t)
			if err := g.Stage(context.Background()); err != nil {
				t.Fatal(err)
			}
			k.observe = func(b []byte) []byte {
				if k.enabled {
					switch change {
					case "revoke":
						a.grant.Fact.Revoked = true
					case "owner":
						a.grant.Fact.Owner.StartTicks++
					case "sequence":
						a.grant.Fact.Sequence++
					case "deadline":
						a.grant.Fact.DeadlineBootNS += int64(time.Second)
					case "work":
						a.grant.WorkHash = strings.Repeat("d", 64)
					case "unavailable":
						a.unavailable = true
					case "expired":
						*now = a.grant.Fact.DeadlineBootNS
					}
				}
				return b
			}
			if err := g.Open(context.Background()); err == nil {
				t.Fatal("stale authority opened")
			}
			if k.enabled || k.token != nil || !g.fenced {
				t.Fatal("not compensated")
			}
		})
	}
}

func TestLeaseGateWrongScopeAndUnverifiedWorkNeverStage(t *testing.T) {
	for _, change := range []string{"namespace", "pid", "incarnation", "link", "desired", "work-format", "LAN-drift", "offload", "forwarding", "address"} {
		t.Run(change, func(t *testing.T) {
			g, k, a, _ := gateFixture(t)
			switch change {
			case "namespace":
				a.grant.Fact.Owner.Namespace++
			case "pid":
				a.grant.Fact.Owner.PID++
			case "incarnation":
				a.grant.Fact.Owner.Incarnation = strings.Repeat("e", 32)
			case "link":
				a.grant.Fact.WAN.Name = "other0"
			case "desired":
				a.grant.Fact.DesiredHash = strings.Repeat("d", 64)
			case "work-format":
				a.grant.WorkHash = "claimed"
			case "LAN-drift", "offload":
				a.verify = func() error { return ErrScope }
			case "forwarding":
				g.closedForwarding = func() error { return ErrScope }
			case "address":
				a.grant.Fact.Address = "127.0.0.1/8"
			}
			if err := g.Stage(context.Background()); err == nil || k.stages != 0 {
				t.Fatal("untrusted grant staged")
			}
		})
	}
}

func TestLeaseGateExpiredKernelTokenCannotOpen(t *testing.T) {
	g, k, _, now := gateFixture(t)
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = k.installed + int64(k.token["timeout"].(float64))*int64(time.Second)
	if err := g.Open(context.Background()); err == nil || k.enabled {
		t.Fatal("expired token opened")
	}
}

func TestLeaseGateClosureFailureNeverClaimsClosed(t *testing.T) {
	g, k, a, _ := gateFixture(t)
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	k.failClose = true
	a.unavailable = true
	if err := g.Verify(context.Background()); !errors.Is(err, ErrLeaseGateUncertain) {
		t.Fatal("missing unproven closure", err)
	}
	if err := g.Open(context.Background()); err == nil {
		t.Fatal("fence reopened")
	}
}

func TestLeaseGateExactProjectionRejectsSemanticDrift(t *testing.T) {
	for _, change := range []string{"accept", "established", "order", "priority", "flowtable", "set-flags", "duplicates", "trailing", "oversized", "missing-expires", "permanent", "overflow"} {
		t.Run(change, func(t *testing.T) {
			g, k, _, _ := gateFixture(t)
			if err := g.Stage(context.Background()); err != nil {
				t.Fatal(err)
			}
			b, _ := k.Observe(context.Background())
			var root map[string]any
			if json.Unmarshal(b, &root) != nil {
				t.Fatal("fixture")
			}
			objects := root["nftables"].([]any)
			rule := objects[4].(map[string]any)["rule"].(map[string]any)
			live := objects[2].(map[string]any)["set"].(map[string]any)
			elem := live["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
			switch change {
			case "accept":
				rule["expr"] = []any{map[string]any{"accept": nil}}
			case "established":
				rule["expr"] = append([]any{map[string]any{"ct": map[string]any{"key": "state"}}}, rule["expr"].([]any)...)
			case "order":
				objects[4], objects[5] = objects[5], objects[4]
			case "priority":
				objects[3].(map[string]any)["chain"].(map[string]any)["prio"] = 0
			case "flowtable":
				objects = append(objects, map[string]any{"flowtable": map[string]any{"name": "bypass"}})
			case "set-flags":
				live["flags"] = []any{"timeout", "dynamic"}
			case "missing-expires":
				delete(elem, "expires")
			case "permanent":
				elem["timeout"] = 0
			case "overflow":
				elem["expires"] = json.Number("9223372036854775807")
			}
			b = leaseGateEncode(objects)
			switch change {
			case "duplicates":
				b = []byte(strings.Replace(string(b), `"family":"inet"`, `"family":"inet","family":"inet"`, 1))
			case "trailing":
				b = append(b, []byte("{}")...)
			case "oversized":
				b = []byte(strings.Repeat(" ", leaseGateMaxJSON+1))
			}
			if _, err := leaseGateRead(b, k.wan, false, true, leaseGateDigest(g.staged), g.timeout); err == nil {
				t.Fatal("accepted semantic drift")
			}
		})
	}
}

func TestLeaseGateOpenBatchTouchesOnlyEnableSet(t *testing.T) {
	var got map[string]any
	if json.Unmarshal(leaseGateOpen("wan0"), &got) != nil {
		t.Fatal("decode")
	}
	want := map[string]any{"nftables": []any{map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": leaseGateTable, "name": "enabled", "elem": []any{"wan0"}}}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("open changes more than enabled")
	}
}

func TestLeaseGateExistingTableIsNeverAdopted(t *testing.T) {
	g, k, _, _ := gateFixture(t)
	if err := g.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	priorToken := k.token
	reopened, err := newLeaseGate(context.Background(), recoveryIdentityFixture(), g.opts, k, g.now, g.closedForwarding)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Initialize(context.Background()); !errors.Is(err, ErrLeaseGateUncertain) {
		t.Fatal("existing table adopted", err)
	}
	if !k.enabled || !reflect.DeepEqual(priorToken, k.token) {
		t.Fatal("foreign table overwritten during failed adoption")
	}
}

func TestLeaseGatePartialStageCannotOpen(t *testing.T) {
	g, k, _, _ := gateFixture(t)
	k.afterApply = func() {
		if k.stages == 1 {
			k.token = nil
		}
	}
	if err := g.Stage(context.Background()); err == nil {
		t.Fatal("missing installed token accepted")
	}
	if err := g.Open(context.Background()); err == nil || k.enabled || !g.fenced {
		t.Fatal("partial stage opened")
	}
}
