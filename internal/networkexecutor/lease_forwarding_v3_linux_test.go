package networkexecutor

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestLeaseForwardingV3RejectsUnownedAndHostDescriptorsWithoutWrites(t *testing.T) {
	before, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	base, _, opts, _, _ := leaseInputs(t)
	if f, err := NewLeaseForwardingInOwnedNamespaceV3(ns, ns, *base.identity, 0, opts.Desired); err == nil {
		_ = f.Close()
		t.Fatal("same host and target accepted")
	}
	if _, err := NewLeaseForwardingInOwnedNamespaceV3(nil, nil, *base.identity, 0, opts.Desired); err == nil {
		t.Fatal("missing descriptors accepted")
	}
	f := &LeaseForwardingV3{}
	calls := 0
	if f.Enable(context.Background(), func(context.Context) error { calls++; return nil }) == nil || f.Disable(context.Background()) == nil || calls != 0 {
		t.Fatal("unowned forwarding mutation admitted")
	}
	if writeLeaseForwardingV3("2\n") == nil {
		t.Fatal("arbitrary forwarding value")
	}
	after, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("host forwarding changed", err)
	}
}
