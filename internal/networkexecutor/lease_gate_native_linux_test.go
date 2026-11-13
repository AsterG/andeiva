//go:build linux

package networkexecutor

import (
	"context"
	"strings"
	"testing"
	"time"
)

type nativeLeaseGateAuthority struct {
	grant    LeaseGateGrant
	executor *LeaseExecutor
}

func (a *nativeLeaseGateAuthority) Current(context.Context) (LeaseGateGrant, error) {
	return a.grant, nil
}
func (a *nativeLeaseGateAuthority) Verify(ctx context.Context, grant LeaseGateGrant) error {
	if grant != a.grant {
		return ErrScope
	}
	return a.executor.Verify(ctx)
}

// This opt-in leaves a short-lived token and owned WAN delta for the enclosing
// root harness to observe after this process exits. Only namespace teardown
// cleans them. Authority is test-controlled, not selected durable work or DHCP.
func TestNativeLeaseGateKernel(t *testing.T) {
	target, host, id, options, fact := nativeLeaseInputs(t, "gate")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fact.DeadlineBootNS = nativeLeaseNow(t) + int64(12*time.Second)
	l, err := NewLeaseInOwnedNamespace(ctx, target, host, id, 0, options)
	if err != nil {
		t.Fatal("lease constructor", err)
	}
	if outcome, err := l.Refresh(ctx); err != nil || outcome != LeaseApplied {
		t.Fatal("lease apply", outcome, err)
	}
	authority := &nativeLeaseGateAuthority{grant: LeaseGateGrant{Fact: *fact, WorkHash: strings.Repeat("a", 64)}, executor: l}
	g, err := NewLeaseGateInOwnedNamespace(ctx, target, host, id, 0, LeaseGateOptions{Desired: options.Desired, Owner: options.Owner, Authority: authority})
	if err != nil {
		t.Fatal("gate constructor", err)
	}
	if err = g.Initialize(ctx); err != nil {
		t.Fatal("gate initialize", err)
	}
	if err = g.Stage(ctx); err != nil {
		if b, e := g.kernel.Observe(ctx); e == nil {
			t.Log("native staged readback", string(b))
		}
		t.Fatal("gate stage", err)
	}
	if err = g.Open(ctx); err != nil {
		t.Fatal("gate open", err)
	}
	if err = g.Verify(ctx); err != nil {
		t.Fatal("gate verify", err)
	}
	t.Logf("kernel gate open; original BOOTTIME deadline=%d; process exits without refreshing token", fact.DeadlineBootNS)
}
