//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
)

type observedHealth struct {
	value firewalladmin.Observation
	err   error
	calls int
}

func (h *observedHealth) Observed(_ context.Context, p configpoc.Principal) (firewalladmin.Observation, error) {
	h.calls++
	if p.Role != configpoc.RoleViewer {
		return firewalladmin.Observation{}, errors.New("health must use read-only role")
	}
	return h.value, h.err
}
func TestHealthFailsForRecoveryAndAuditExhaustion(t *testing.T) {
	path := privateDir(t)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	a, err := openAuditBounded(path, uid, gid, 128, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.Close() }()
	h := &observedHealth{value: firewalladmin.Observation{Hash: "effective", Phase: "idle"}}
	ctx := context.Background()
	if !available(ctx, h, a) {
		t.Fatal("healthy service rejected")
	}
	h.value.RecoveryRequired = true
	if available(ctx, h, a) {
		t.Fatal("core recovery ignored")
	}
	h.value.RecoveryRequired = false
	for _, phase := range []string{"blocked", "bootstrap", "unknown", ""} {
		h.value.Phase = phase
		if available(ctx, h, a) {
			t.Fatal("invalid guardian phase accepted", phase)
		}
	}
	h.value.Phase = "idle"
	h.err = errors.New("unavailable")
	if available(ctx, h, a) {
		t.Fatal("authority failure ignored")
	}
	h.err = nil
	event := adminauth.Event{At: time.Now().UTC(), Actor: "admin-a", Action: "login", Result: "ok"}
	if a.Append(event) != nil || !available(ctx, h, a) {
		t.Fatal("audit capacity check failed")
	}
	if a.Append(event) != nil {
		t.Fatal("second audit segment")
	}
	before := h.calls
	if available(ctx, h, a) || h.calls != before {
		t.Fatal("audit exhaustion did not short circuit")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = openAuditBounded(path, uid, gid, 128, 2)
	if err != nil {
		t.Fatal(err)
	}
	if available(ctx, h, a) {
		t.Fatal("restart bypassed audit capacity check")
	}
}

type healthAuthority struct{ engine *configpoc.SimEngine }

func (a healthAuthority) Arm(context.Context, string, configpoc.Revision, configpoc.Revision, time.Duration) error {
	return errors.New("not used")
}
func (a healthAuthority) Confirm(context.Context, string, string) error {
	return errors.New("not used")
}
func (a healthAuthority) Current(context.Context) (string, error) { return a.engine.Current(), nil }
func (a healthAuthority) State(context.Context) (firewalladmin.LeaseState, error) {
	return firewalladmin.LeaseState{Phase: "idle"}, nil
}
func TestHealthObservesActualCoreRecovery(t *testing.T) {
	engine := configpoc.NewSimEngine("health")
	initial := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	core, err := configpoc.Open(privateDir(t), []configpoc.Engine{engine}, configpoc.Options{Initial: &initial})
	if err != nil {
		t.Fatal(err)
	}
	service, err := firewalladmin.New(core, healthAuthority{engine})
	if err != nil {
		core.Close()
		t.Fatal(err)
	}
	defer service.Close()
	a, err := openAudit(privateDir(t), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !available(context.Background(), service, a) {
		t.Fatal("consistent core rejected")
	}
	engine.Drift("unexpected")
	if available(context.Background(), service, a) {
		t.Fatal("real core inconsistency ignored while guardian idle")
	}
}

func TestHealthRejectsAuditFailureAndClosedLog(t *testing.T) {
	a, err := openAudit(privateDir(t), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	h := &observedHealth{value: firewalladmin.Observation{Hash: "effective", Phase: "idle"}}
	if err = a.Append(adminauth.Event{At: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("invalid event accepted")
	}
	if available(context.Background(), h, a) {
		t.Fatal("latched audit failure ignored")
	}
	a.Close()
	if a.Ready() {
		t.Fatal("closed audit ready")
	}
}
