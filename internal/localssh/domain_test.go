package localssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// Only policy application/observation is simulated here. SSH, authentication,
// coordinator persistence, proof generation and transaction admission are real.
type domainEngine struct {
	mu       sync.Mutex
	revision configpoc.Revision
	lease    firewalladmin.LeaseState
}

func (e *domainEngine) Name() string { return "domain-test" }
func (e *domainEngine) Validate(c configpoc.Config) error {
	_, err := configpoc.Canonical(c)
	return err
}
func (e *domainEngine) Apply(_ context.Context, r configpoc.Revision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revision = r
	return nil
}
func (e *domainEngine) Current() string { e.mu.Lock(); defer e.mu.Unlock(); return e.revision.Hash }

type domainAuthority struct{ e *domainEngine }

func (a domainAuthority) Current(context.Context) (string, error) { return a.e.Current(), nil }
func (a domainAuthority) Arm(_ context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	a.e.mu.Lock()
	defer a.e.mu.Unlock()
	a.e.lease = firewalladmin.LeaseState{Phase: "armed", ID: id, Previous: previous.Hash, Target: target.Hash, Deadline: time.Now().Add(ttl)}
	return nil
}
func (a domainAuthority) State(context.Context) (firewalladmin.LeaseState, error) {
	a.e.mu.Lock()
	defer a.e.mu.Unlock()
	return a.e.lease, nil
}
func (a domainAuthority) Confirm(_ context.Context, id, hash string) error {
	a.e.mu.Lock()
	defer a.e.mu.Unlock()
	a.e.lease.Phase = "idle"
	a.e.lease.ID = id
	a.e.lease.Target = hash
	return nil
}
func (e *domainEngine) Observe(context.Context) (localadmin.ObservedState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.revision
	a, err := localpolicy.Compile(*r.Config.LocalServices)
	if err != nil {
		return localadmin.ObservedState{}, err
	}
	o := localpolicy.Observation{Revision: a.Revision.Hash, Rules: a.Rules, Listeners: []localpolicy.Listener{}}
	for _, s := range r.Config.LocalServices.Services {
		if s.Enabled {
			for _, b := range s.Bindings {
				o.Listeners = append(o.Listeners, localpolicy.Listener{Owner: s.Owner, Service: s.ID, Interface: b.Interface, LocalAddress: b.LocalAddress, Protocol: s.Endpoints[0].Protocol, Port: s.Endpoints[0].FirstPort})
			}
		}
	}
	return localadmin.ObservedState{Hash: r.Hash, Local: o}, nil
}

func TestSSHSharedRecoverySessionRealCoordinatorTransactions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("durable coordinator requires Linux")
	}
	var domain *localadmin.Service
	var initial, target configpoc.Revision
	h := newHarness(t, "admin", func(s *Server) {
		listener := s.options.Listener
		inventory := []localpolicy.Interface{{Name: listener.Interface, Zone: localpolicy.LAN, Addresses: []string{listener.LocalAddress}}}
		service, err := localpolicy.DefaultManagement("management", "ssh", inventory[0], listener.LocalAddress, []string{"127.0.0.1/32"})
		if err != nil {
			t.Fatal(err)
		}
		service.Kind = localpolicy.ManagementSSH
		service.Enabled = false
		service.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: listener.Port, LastPort: listener.Port}}
		config := configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: inventory, Services: []localpolicy.Service{service}}}
		initial, err = configpoc.Canonical(config)
		if err != nil {
			t.Fatal(err)
		}
		config.LocalServices.Services[0].Enabled = true
		target, err = configpoc.Canonical(config)
		if err != nil {
			t.Fatal(err)
		}
		engine := &domainEngine{lease: firewalladmin.LeaseState{Phase: "idle"}}
		core, err := configpoc.Open(filepath.Join(t.TempDir(), "state"), []configpoc.Engine{engine}, configpoc.Options{Initial: &initial.Config})
		if err != nil {
			t.Fatal(err)
		}
		domain, err = localadmin.New(core, localadmin.Options{RunID: strings.Repeat("a", 32), RecoveryEndpointID: "recovery", Inventory: inventory, Authority: domainAuthority{engine}, Observer: engine})
		if err != nil {
			t.Fatal(err)
		}
		s.options.Backend = domain
		s.options.ActivationHash = target.Hash
	}, nil)
	t.Cleanup(func() { _ = domain.Close() })
	credential := h.credential
	identity, token, err := h.auth.Login("operator", credential)
	if err != nil {
		t.Fatal(err)
	}
	h.credential = "session:" + token
	hash := sha256.Sum256([]byte(token))
	recovery := localadmin.Context{Principal: configpoc.Principal{ID: identity.Username, Role: configpoc.RoleAdmin}, Surface: configpoc.API, SessionHash: hex.EncodeToString(hash[:]), EndpointID: "recovery"}
	status := func() configpoc.Snapshot {
		t.Helper()
		s, err := domain.Status(context.Background(), recovery)
		if err != nil {
			t.Fatal(err)
		}
		return s.Snapshot
	}
	sequence := 0
	request := func(op string) localadmin.Request {
		sequence++
		return localadmin.Request{Transaction: configpoc.Request{Operation: op, Key: fmt.Sprintf("ssh-domain-%d", sequence), ExpectedGeneration: status().Generation}}
	}
	run := func(r localadmin.Request) configpoc.Snapshot {
		t.Helper()
		input, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		output, err := h.run(t, "andeiva local-services execute", string(input))
		if err != nil {
			t.Fatalf("domain execute %s: %s %v", r.Transaction.Operation, output, err)
		}
		var response struct {
			Data configpoc.Snapshot `json:"data"`
		}
		if err = json.Unmarshal(output, &response); err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	recoveryProof := func(c localadmin.Context, r localadmin.Request, target, lease string) string {
		t.Helper()
		p, err := domain.IssueProof(c, localadmin.ProofRequest{Generation: r.Transaction.ExpectedGeneration, Target: target, Lease: lease})
		if err != nil {
			t.Fatal(err)
		}
		return p.Token
	}
	stage := request(configpoc.OpStage)
	stage.Transaction.Config = &target.Config
	run(stage)
	run(request(configpoc.OpValidate))
	commit := request(configpoc.OpCommit)
	commit.Transaction.ConfirmFor = 30 * time.Second
	// A future tuple and even the future listener hash cannot preissue proof.
	future := localadmin.ProofRequest{Generation: commit.Transaction.ExpectedGeneration + 1, Target: target.Hash, Lease: commit.Transaction.Key}
	input, _ := json.Marshal(future)
	output, err := h.run(t, "andeiva local-services proof", string(input))
	if err == nil || !strings.Contains(string(output), configpoc.ErrDenied.Error()) {
		t.Fatalf("preissued endpoint proof: %s %v", output, err)
	}
	_, otherToken, err := h.auth.Login("operator", credential)
	if err != nil {
		t.Fatal(err)
	}
	other := recovery
	otherHash := sha256.Sum256([]byte(otherToken))
	other.SessionHash = hex.EncodeToString(otherHash[:])
	commit.RecoveryProof = recoveryProof(other, commit, target.Hash, commit.Transaction.Key)
	input, _ = json.Marshal(commit)
	output, err = h.run(t, "andeiva local-services execute", string(input))
	if err == nil || !strings.Contains(string(output), configpoc.ErrDenied.Error()) {
		t.Fatal("foreign recovery session accepted")
	}
	commit.RecoveryProof = recoveryProof(recovery, commit, target.Hash, commit.Transaction.Key)
	pending := run(commit)
	if pending.Pending == nil {
		t.Fatal("commit has no pending lease")
	}
	proofRequest := localadmin.ProofRequest{Generation: pending.Generation, Target: pending.Running.Hash, Lease: pending.Pending.Lease}
	input, _ = json.Marshal(proofRequest)
	output, err = h.run(t, "andeiva local-services proof", string(input))
	if err != nil {
		t.Fatalf("managed proof: %s %v", output, err)
	}
	var proofResponse struct {
		Data localadmin.Proof `json:"data"`
	}
	if err = json.Unmarshal(output, &proofResponse); err != nil || len(proofResponse.Data.Token) != 64 {
		t.Fatal("no real domain proof")
	}
	confirm := request(configpoc.OpConfirm)
	confirm.Transaction.Target = pending.Running.Hash
	confirm.RecoveryProof = recoveryProof(recovery, confirm, pending.Running.Hash, pending.Pending.Lease)
	confirm.EndpointProofs = []string{proofResponse.Data.Token}
	confirmed := run(confirm)
	if confirmed.Pending != nil {
		t.Fatal("confirm not published")
	}
	save := request(configpoc.OpSave)
	save.RecoveryProof = recoveryProof(recovery, save, confirmed.Running.Hash, save.Transaction.Key)
	saved := run(save)
	if saved.Startup.Hash != target.Hash {
		t.Fatal("save did not persist startup")
	}
	rollback := request(configpoc.OpRollback)
	rollback.Transaction.Target = initial.Hash
	rollback.Transaction.ConfirmFor = 30 * time.Second
	rollback.RecoveryProof = recoveryProof(recovery, rollback, initial.Hash, rollback.Transaction.Key)
	rolled := run(rollback)
	if rolled.Pending == nil || rolled.Running.Hash != initial.Hash {
		t.Fatal("rollback not pending")
	}
	// Disabling SSH is confirmed through the independent recovery context. The
	// unit engine is intentionally not evidence of socket retirement/nft rules.
	finish := request(configpoc.OpConfirm)
	finish.Transaction.Target = initial.Hash
	finish.RecoveryProof = recoveryProof(recovery, finish, initial.Hash, rolled.Pending.Lease)
	if _, err = domain.Execute(context.Background(), recovery, finish); err != nil {
		t.Fatal(err)
	}
	if _, err = h.auth.Authenticate(token); err != nil {
		t.Fatal("borrowed HTTPS session revoked")
	}
	if err = h.auth.Logout(otherToken); err != nil {
		t.Fatal(err)
	}
	if err = h.auth.Logout(token); err != nil {
		t.Fatal(err)
	}
}
