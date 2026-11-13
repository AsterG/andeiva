package networkexecutor

import (
	"context"
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestLeaseGateFixedLinuxCommands(t *testing.T) {
	for op, want := range map[leaseGateOperation][]string{
		leaseGateCheck:   {"/usr/sbin/nft", "--check", "-j", "-f", "-"},
		leaseGateApply:   {"/usr/sbin/nft", "-j", "-f", "-"},
		leaseGateObserve: {"/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", "andeiva_lease_gate"},
	} {
		cmd, err := leaseGateCommand(context.Background(), op)
		if err != nil || cmd.Path != "/usr/sbin/nft" || !reflect.DeepEqual(cmd.Args, want) || cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || cmd.SysProcAttr.Cloneflags != 0 || len(cmd.ExtraFiles) != 0 {
			t.Fatal("command escaped fixed profile", op, err)
		}
	}
	if cmd, err := leaseGateCommand(context.Background(), 0); err == nil || cmd != nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestLeaseGateLinuxConstructorRefusesHostAndMissingAuthority(t *testing.T) {
	e, _, opts, _, _ := leaseInputs(t)
	id := *e.identity
	id.Host = id.Namespace
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if g, err := NewLeaseGateInOwnedNamespace(context.Background(), file, file, id, 0, LeaseGateOptions{Desired: opts.Desired, Owner: opts.Owner}); err == nil || g != nil {
		t.Fatal("host target accepted")
	}
	if g, err := NewLeaseGateInOwnedNamespace(nil, file, file, *e.identity, 0, LeaseGateOptions{}); err == nil || g != nil {
		t.Fatal("missing lifetime accepted")
	}
}

func TestLeaseGateConstructorRejectsInvalidScopeWithoutMutation(t *testing.T) {
	for _, change := range []string{"host", "owner", "nil-authority", "invalid-desired", "forwarding"} {
		t.Run(change, func(t *testing.T) {
			e, _, opts, f, now := leaseInputs(t)
			id := *e.identity
			a := &gateAuthorityFake{grant: LeaseGateGrant{Fact: *f}}
			o := LeaseGateOptions{Desired: opts.Desired, Owner: opts.Owner, Authority: a}
			closed := func() error { return nil }
			switch change {
			case "host":
				id.Host = id.Namespace
			case "owner":
				o.Owner.Namespace++
			case "nil-authority":
				o.Authority = nil
			case "invalid-desired":
				o.Desired.Hash = "invalid"
			case "forwarding":
				closed = func() error { return ErrScope }
			}
			k := &gateKernelFake{wan: f.WAN.Name, now: now}
			g, err := newLeaseGate(context.Background(), id, o, k, func() (int64, error) { return *now, nil }, closed)
			if g != nil || err == nil || k.applies != 0 {
				t.Fatal("invalid scope mutated or accepted")
			}
		})
	}
}
