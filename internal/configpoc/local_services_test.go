package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func localSample(t *testing.T, port uint16) Config {
	t.Helper()
	lan := localpolicy.Interface{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"192.0.2.1"}}
	service, err := localpolicy.DefaultManagement("management", "https", lan, "192.0.2.1", []string{"192.0.2.10/32"})
	if err != nil {
		t.Fatal(err)
	}
	service.Endpoints[0] = localpolicy.Endpoint{Protocol: localpolicy.TCP, FirstPort: port, LastPort: port}
	return Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{
		SchemaVersion: localpolicy.SchemaVersion, Interfaces: []localpolicy.Interface{lan}, Services: []localpolicy.Service{service},
	}}
}

func confirmLocal(t *testing.T, s *Service, snap Snapshot) Snapshot {
	t.Helper()
	out, err := s.Execute(context.Background(), admin, API, Request{Operation: OpConfirm, Key: fmt.Sprintf("confirm-%d", snap.Generation), ExpectedGeneration: snap.Generation, Target: snap.Running.Hash})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func commitLocal(t *testing.T, s *Service, c Config) Snapshot {
	t.Helper()
	invoke(t, s, OpStage, &c, 0)
	return confirmLocal(t, s, invoke(t, s, OpCommit, nil, time.Second))
}

func TestLocalCanonicalVersionIsolation(t *testing.T) {
	c := localSample(t, 18443)
	c.LocalServices.Services[0].Bindings[0].Sources = []string{"192.0.2.11/32", "192.0.2.10/32"}
	r, err := Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	c.LocalServices.Services[0].Bindings[0].Sources[0] = "192.0.2.12/32"
	if got := r.Config.LocalServices.Services[0].Bindings[0].Sources; got[0] != "192.0.2.10/32" || got[1] != "192.0.2.11/32" {
		t.Fatal("local declarations not independently canonicalized", got)
	}
	changed, err := Canonical(c)
	if err != nil || changed.Hash == r.Hash {
		t.Fatal("local permission change omitted from shared revision", err)
	}
	reordered := clone(r.Config)
	sources := reordered.LocalServices.Services[0].Bindings[0].Sources
	sources[0], sources[1] = sources[1], sources[0]
	same, err := Canonical(reordered)
	if err != nil || same.Hash != r.Hash {
		t.Fatal("local set order changed shared revision", err)
	}
	for name, mutate := range map[string]func(*Config){
		"v1_local":              func(c *Config) { c.SchemaVersion = 1 },
		"v2_local":              func(c *Config) { c.SchemaVersion = 2 },
		"missing_local":         func(c *Config) { c.LocalServices = nil },
		"unknown_local_schema":  func(c *Config) { c.LocalServices.SchemaVersion = 99 },
		"unknown_config_schema": func(c *Config) { c.SchemaVersion = 4 },
		"implicit_sources":      func(c *Config) { c.LocalServices.Services[0].Bindings[0].Sources = nil },
		"legacy_forwarding":     func(c *Config) { c.Rules = sample("legacy").Rules },
		"local_capacity": func(c *Config) {
			c.LocalServices.Services = make([]localpolicy.Service, localpolicy.MaxServices+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := localSample(t, 18443)
			mutate(&bad)
			if _, err := Canonical(bad); !errors.Is(err, ErrInvalid) {
				t.Fatal("accepted invalid mixed schema", err)
			}
		})
	}
	c = localSample(t, 18443)
	c.Rules = firewallSample().Rules
	if _, err := Canonical(c); err != nil {
		t.Fatal("schema 3 must preserve typed forwarding", err)
	}
}

func TestLegacyWireAndJournalGoldenWithLocalExtension(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			configJSON := fmt.Sprintf(`{"schema_version":%d,"default_action":"deny","rules":[]}`, version)
			r, err := Canonical(Config{SchemaVersion: version, DefaultAction: "deny"})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(r.Config)
			digest := sha256.Sum256([]byte(configJSON))
			if string(encoded) != configJSON || r.Hash != hex.EncodeToString(digest[:]) {
				t.Fatal("legacy canonical bytes changed")
			}
			requestJSON := fmt.Sprintf(`{"operation":"stage","key":"golden","expected_generation":7,"config":%s}`, configJSON)
			req := Request{Operation: OpStage, Key: "golden", ExpectedGeneration: 7, Config: &r.Config}
			encoded, _ = json.Marshal(req)
			if string(encoded) != requestJSON {
				t.Fatal("legacy request fingerprint input changed", string(encoded))
			}
			requestDigest := sha256.Sum256([]byte(requestJSON))
			fingerprint := hex.EncodeToString(requestDigest[:])
			revisionJSON := fmt.Sprintf(`{"hash":%q,"config":%s}`, r.Hash, configJSON)
			recordJSON := fmt.Sprintf(`{"previous":"","state":{"snapshot":{"generation":7,"running":%s,"startup":%s,"last_good":%s,"recovery_required":false,"revoked":[]},"receipts":{"alice:golden":{"fingerprint":%q,"generation":7}}},"audit":{"sequence":1,"at":"1970-01-01T00:00:00Z","actor":"alice","surface":"api","operation":"stage","result":"ok","running_hash":%q},"hash":""}`, revisionJSON, revisionJSON, revisionJSON, fingerprint, r.Hash)
			record := journalRecord{State: durableState{Snapshot: Snapshot{Generation: 7, Running: r, Startup: r, LastGood: r, Revoked: []string{}}, Receipts: map[string]receipt{"alice:golden": {Fingerprint: fingerprint, Generation: 7}}}, Audit: Audit{Sequence: 1, At: time.Unix(0, 0).UTC(), Actor: "alice", Surface: API, Operation: OpStage, Result: "ok", RunningHash: r.Hash}}
			encoded, _ = json.Marshal(record)
			recordDigest := sha256.Sum256([]byte(recordJSON))
			if string(encoded) != recordJSON || recordHash(record) != hex.EncodeToString(recordDigest[:]) {
				t.Fatal("legacy journal bytes/hash changed", string(encoded))
			}
		})
	}
}

func TestLocalExplicitMigrationReopenAndLegacyReplay(t *testing.T) {
	initial := firewallSample()
	s, engines, dir := fixture(t, Options{Initial: &initial})
	before := status(t, s)
	legacyRequest := Request{Operation: OpStage, Key: "legacy-stage", ExpectedGeneration: before.Generation, Config: &initial}
	if _, err := s.Execute(context.Background(), admin, CLI, legacyRequest); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			original[entry.Name()] = b
		}
	}
	c := localSample(t, 18443)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{Initial: &c})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if status(t, s).Running.Config.SchemaVersion != 2 {
		t.Fatal("Open silently migrated existing store")
	}
	migrated := commitLocal(t, s, c)
	if migrated.Startup.Hash != before.Startup.Hash {
		t.Fatal("commit implicitly saved migration")
	}
	replayed, err := s.Execute(context.Background(), admin, Web, legacyRequest)
	if err != nil || replayed.ReplayedGeneration == 0 || replayed.Running.Hash != migrated.Running.Hash {
		t.Fatal("legacy replay changed after migration", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if status(t, s).Running.Hash != migrated.Running.Hash {
		t.Fatal("service restart lost confirmed schema 3")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	if status(t, s).Running.Hash != before.Startup.Hash {
		t.Fatal("boot ignored unsaved legacy Startup")
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(want) {
			t.Fatal("historical journal rewritten", name, err)
		}
	}
}

func TestLocalCommitRequiresConfirmationBeforeAuthority(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	c := localSample(t, 18443)
	staged := invoke(t, s, OpStage, &c, 0)
	g := &testGuard{}
	req := Request{Operation: OpCommit, Key: "unconfirmed", ExpectedGeneration: staged.Generation}
	for _, managed := range []bool{false, true} {
		var err error
		if managed {
			_, err = s.ExecuteManaged(context.Background(), admin, API, req, g)
		} else {
			_, err = s.Execute(context.Background(), admin, API, req)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("local changes accepted without confirmation", err)
		}
	}
	if g.arms != 0 || g.confirms != 0 {
		t.Fatal("invalid request reached authority")
	}
	commitLocal(t, s, c)
	c.Rules = firewallSample().Rules
	invoke(t, s, OpStage, &c, 0)
	if got := invoke(t, s, OpCommit, nil, 0); got.Pending != nil {
		t.Fatal("unchanged local services forced forwarding-only confirmation")
	}
}

func TestLocalHistoricalRollbackConfirmationAndDenials(t *testing.T) {
	c := localSample(t, 18443)
	s, _, _ := fixture(t, Options{Initial: &c})
	first := status(t, s)
	c.LocalServices.Services[0].Endpoints[0] = localpolicy.Endpoint{Protocol: localpolicy.TCP, FirstPort: 19443, LastPort: 19443}
	current := commitLocal(t, s, c)
	g := &testGuard{}
	base := Request{Operation: OpRollback, Key: "rollback", ExpectedGeneration: current.Generation, Target: first.Running.Hash, ConfirmFor: 30 * time.Second}
	for name, change := range map[string]func(*Request, *Principal){
		"no_window": func(r *Request, _ *Principal) { r.ConfirmFor = 0 },
		"short":     func(r *Request, _ *Principal) { r.ConfirmFor = time.Second },
		"long":      func(r *Request, _ *Principal) { r.ConfirmFor = 121 * time.Second },
		"negative":  func(r *Request, _ *Principal) { r.ConfirmFor = -time.Second },
		"stale":     func(r *Request, _ *Principal) { r.ExpectedGeneration-- },
		"unknown":   func(r *Request, _ *Principal) { r.Target = fmt.Sprintf("%064d", 1) },
		"viewer":    func(_ *Request, p *Principal) { p.Role = RoleViewer },
	} {
		r, p := base, admin
		r.Key = name
		change(&r, &p)
		if _, err := s.ExecuteManaged(context.Background(), p, Web, r, g); err == nil {
			t.Fatal("accepted invalid rollback", name)
		}
	}
	if g.arms != 0 || g.confirms != 0 {
		t.Fatal("denied rollback reached authority")
	}
	out, err := s.ExecuteManaged(context.Background(), admin, Web, base, g)
	if err != nil {
		t.Fatal(err)
	}
	if out.Pending == nil || out.Pending.Previous.Hash != current.Running.Hash || out.Pending.Lease != base.Key || out.Running.Hash != first.Running.Hash || out.LastGood.Hash != current.Running.Hash || g.arms != 1 || g.confirms != 0 {
		t.Fatal("rollback was not provisional")
	}
	if _, err := s.ExecuteManaged(context.Background(), admin, CLI, Request{Operation: OpSave, Key: "pending-save", ExpectedGeneration: out.Generation}, g); !errors.Is(err, ErrPending) {
		t.Fatal("saved unconfirmed rollback", err)
	}
	confirm := Request{Operation: OpConfirm, Key: "rollback-confirm", ExpectedGeneration: out.Generation, Target: out.Running.Hash}
	if _, err := s.ExecuteManaged(context.Background(), Principal{"bob", RoleAdmin}, API, confirm, g); !errors.Is(err, ErrDenied) {
		t.Fatal("other owner confirmed rollback", err)
	}
	confirmed, err := s.ExecuteManaged(context.Background(), admin, API, confirm, g)
	if err != nil || confirmed.Pending != nil || confirmed.LastGood.Hash != first.Running.Hash || g.confirms != 1 {
		t.Fatal("confirmation failed", err)
	}
	replay, err := s.ExecuteManaged(context.Background(), admin, CLI, base, g)
	if err != nil || replay.ReplayedGeneration != out.Generation || replay.Pending != nil || g.arms != 1 {
		t.Fatal("rollback replay rearmed lease", err)
	}
	base.ConfirmFor = 31 * time.Second
	if _, err := s.ExecuteManaged(context.Background(), admin, API, base, g); !errors.Is(err, ErrReplay) {
		t.Fatal("changed rollback window replay accepted", err)
	}
	if saved := invoke(t, s, OpSave, nil, 0); saved.Startup.Hash != first.Running.Hash {
		t.Fatal("confirmed rollback not saved")
	}
}

func TestLocalRollbackExpiryAndRestartRestorePrevious(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint(restart), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				legacy := firewallSample()
				s, engines, dir := fixture(t, Options{Initial: &legacy})
				initial := status(t, s)
				current := commitLocal(t, s, localSample(t, 18443))
				ttl := 150 * time.Millisecond
				if restart {
					ttl = time.Minute
				}
				out, err := s.Execute(context.Background(), admin, API, Request{Operation: OpRollback, Key: "legacy-rollback", ExpectedGeneration: current.Generation, Target: initial.Running.Hash, ConfirmFor: ttl})
				if err != nil || out.Pending == nil || out.Running.Config.SchemaVersion != 2 {
					t.Fatal("legacy rollback failed", err)
				}
				if restart {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
				} else {
					time.Sleep(ttl)
					synctest.Wait()
					s.mu.Lock()
					expired := s.state.Snapshot.Pending == nil && s.state.Snapshot.Running.Hash == current.Running.Hash
					s.mu.Unlock()
					if !expired {
						t.Fatal("timer did not restore the previous revision before a status request")
					}
				}
				after := status(t, s)
				if after.Pending != nil || after.Running.Hash != current.Running.Hash || after.Startup.Hash != initial.Startup.Hash || after.RecoveryRequired {
					t.Fatal("rollback safety recovery lost previous schema 3")
				}
			})
		})
	}
}

func TestLocalRollbackConcurrentAdministrators(t *testing.T) {
	initial := localSample(t, 18443)
	s, _, _ := fixture(t, Options{Initial: &initial})
	before := status(t, s)
	current := commitLocal(t, s, localSample(t, 19443))
	results := make(chan error, 2)
	for _, id := range []string{"alice", "bob"} {
		go func() {
			_, err := s.Execute(context.Background(), Principal{id, RoleAdmin}, API, Request{Operation: OpRollback, Key: id + "-rollback", ExpectedGeneration: current.Generation, Target: before.Running.Hash, ConfirmFor: time.Minute})
			results <- err
		}()
	}
	wins, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("concurrent rollback ownership not serialized", wins, conflicts)
	}
}

func TestLocalSavedBootAndRollbackFromLegacy(t *testing.T) {
	legacy := firewallSample()
	s, engines, dir := fixture(t, Options{Initial: &legacy})
	initial := status(t, s)
	local := commitLocal(t, s, localSample(t, 18443))
	saved := invoke(t, s, OpSave, nil, 0)
	out, err := s.Execute(context.Background(), admin, API, Request{Operation: OpRollback, Key: "remove-local", ExpectedGeneration: saved.Generation, Target: initial.Running.Hash, ConfirmFor: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	out = confirmLocal(t, s, out)
	if out.Running.Config.LocalServices != nil {
		t.Fatal("legacy rollback inferred local services")
	}
	if _, err = s.Execute(context.Background(), admin, API, Request{Operation: OpRollback, Key: "unprotected-local", ExpectedGeneration: out.Generation, Target: local.Running.Hash}); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy to local rollback did not require confirmation", err)
	}
	out, err = s.Execute(context.Background(), admin, API, Request{Operation: OpRollback, Key: "restore-local", ExpectedGeneration: out.Generation, Target: local.Running.Hash, ConfirmFor: time.Second})
	if err != nil || out.Pending == nil {
		t.Fatal("legacy to local rollback failed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after := status(t, s)
	if after.Running.Hash != saved.Startup.Hash || after.Pending != nil || after.Running.Config.SchemaVersion != 3 {
		t.Fatal("boot failed to select saved schema 3 over pending transition")
	}
}

func TestLegacyOnlyRollbackRetainsImmediateSemantics(t *testing.T) {
	c := firewallSample()
	s, _, _ := fixture(t, Options{Initial: &c})
	before := status(t, s)
	c.Rules[0].Action = "deny"
	invoke(t, s, OpStage, &c, 0)
	current := invoke(t, s, OpCommit, nil, 0)
	req := Request{Operation: OpRollback, Key: "legacy-window", ExpectedGeneration: current.Generation, Target: before.Running.Hash, ConfirmFor: time.Second}
	if _, err := s.Execute(context.Background(), admin, API, req); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy rollback acquired new window semantics", err)
	}
	req.Key, req.ConfirmFor = "legacy-immediate", 0
	out, err := s.Execute(context.Background(), admin, API, req)
	if err != nil || out.Pending != nil || out.LastGood.Hash != before.Running.Hash {
		t.Fatal("legacy rollback changed", err)
	}
}

func TestLocalForeignCandidateAndOversizeDeniedBeforeAuthority(t *testing.T) {
	c := localSample(t, 18443)
	s, _, _ := fixture(t, Options{Initial: &c})
	initial := status(t, s)
	staged := invoke(t, s, OpStage, &c, 0)
	g := &testGuard{}
	_, err := s.ExecuteManaged(context.Background(), Principal{"bob", RoleAdmin}, API, Request{Operation: OpRollback, Key: "foreign-candidate", ExpectedGeneration: staged.Generation, Target: initial.Running.Hash, ConfirmFor: 30 * time.Second}, g)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("rollback stole candidate", err)
	}
	c.LocalServices.Services = make([]localpolicy.Service, localpolicy.MaxServices+1)
	_, err = s.ExecuteManaged(context.Background(), admin, API, Request{Operation: OpStage, Key: "oversize-local", ExpectedGeneration: staged.Generation, Config: &c}, g)
	if !errors.Is(err, ErrInvalid) || g.arms != 0 || g.confirms != 0 {
		t.Fatal("invalid local declarations reached authority", err)
	}
	after := status(t, s)
	if after.Generation != staged.Generation || after.Running.Hash != initial.Running.Hash || after.Candidate.Owner != admin.ID {
		t.Fatal("denied request changed configuration")
	}
}
