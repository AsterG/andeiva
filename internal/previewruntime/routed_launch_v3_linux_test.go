//go:build linux

package previewruntime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

func TestRoutedLaunchV3FixedIdentityCommands(t *testing.T) {
	ids := Identities{SchemaVersion: 1, APIUID: 1001, APIGID: 1002, HelperUID: 1003, IPCGID: 1004}
	for _, role := range []string{RoutedAPIRoleV3, RoutedHelperRoleV3} {
		exe, args, e := routedLaunchArgsV3(role, "/opt/andeiva/run", ids, 1005)
		if e != nil {
			t.Fatal(e)
		}
		want := []string{"--reuid=1001", "--regid=1002", "--groups=1004", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/opt/andeiva/run", role}
		if role == RoutedHelperRoleV3 {
			want = []string{"--net=/proc/self/fd/3", "--", "/usr/bin/setpriv", "--reuid=1003", "--regid=1004", "--groups=1005", "--bounding-set=-all,+net_admin", "--inh-caps=-all,+net_admin", "--ambient-caps=-all,+net_admin", "--no-new-privs", "--", "/opt/andeiva/run", role}
			if exe != "/usr/bin/nsenter" {
				t.Fatal("helper escaped namespace entry")
			}
		} else if exe != "/usr/bin/setpriv" {
			t.Fatal("API unexpectedly enters namespace")
		}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("unexpected command %v", args)
		}
	}
	for _, role := range []string{"", "helper", "--shell", "--andeiva-routed-helper-v3;exec"} {
		if _, _, e := routedLaunchArgsV3(role, "/opt/andeiva/run", ids, 1005); e == nil {
			t.Fatal("arbitrary role accepted")
		}
	}
	for _, reader := range []uint32{0, ids.APIGID, ids.IPCGID} {
		if _, _, e := routedLaunchArgsV3(RoutedAPIRoleV3, "/opt/andeiva/run", ids, reader); e == nil {
			t.Fatal("shared group accepted")
		}
	}
	if _, _, e := routedLaunchArgsV3(RoutedAPIRoleV3, "relative", ids, 1005); e == nil {
		t.Fatal("relative executable accepted")
	}
	if s, e := StartRoutedLaunchV3(context.Background(), RoutedLaunchResourcesV3{}, nil); e == nil || s != nil {
		t.Fatal("missing scope launched")
	}
	if e := trustedRoutedExecutableV3(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("untrusted executable accepted")
	}
}

func TestRoutedLaunchV3RootParentStatus(t *testing.T) {
	valid := "Name:\tsupervisor\nPid:\t123\nUid:\t0\t0\t0\t0\n"
	if !rootRoutedParentStatusV3([]byte(valid), 123) {
		t.Fatal("root parent rejected")
	}
	for _, value := range []string{"", strings.Replace(valid, "0\t0\t0\t0", "1000\t1000\t1000\t1000", 1), strings.Replace(valid, "0\t0\t0\t0", "1000\t0\t0\t0", 1), strings.Replace(valid, "123", "124", 1), valid + "Uid:\t0\t0\t0\t0\n", strings.Repeat("x", 65537)} {
		if rootRoutedParentStatusV3([]byte(value), 123) {
			t.Fatal("substituted parent accepted")
		}
	}
}

func TestRoutedLaunchV3EventBindingAndPipeBounds(t *testing.T) {
	for _, tc := range []struct {
		event string
		epoch uint64
		ok    bool
	}{{"controller_ready", 2, true}, {"api_ready", 2, false}, {"controller_ready", 1, false}} {
		c := &routedLaunchChildV3{events: make(chan routedLaunchEventV3, 1), done: make(chan struct{})}
		c.events <- routedLaunchEventV3{Event: tc.event, Epoch: tc.epoch}
		if (c.waitEvent(context.Background(), "controller_ready", 2) == nil) != tc.ok {
			t.Fatal("stale/wrong readiness accepted")
		}
	}
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	if e = writeRoutedLaunchV3(write, strings.Repeat("x", routedLaunchFrameV3)); e == nil {
		t.Fatal("unbounded bootstrap accepted")
	}
	if e = writeRoutedLaunchV3(nil, struct{}{}); e == nil {
		t.Fatal("nil handoff accepted")
	}
	if e = writeRoutedLaunchV3(write, routedLaunchControlV3{Epoch: 1, PID: 42}); e != nil {
		t.Fatal(e)
	}
	var data [256]byte
	n, e := read.Read(data[:])
	if e != nil {
		t.Fatal(e)
	}
	var frame routedLaunchControlV3
	if firewallipc.Decode(data[:n], &frame) != nil || frame.Epoch != 1 || frame.PID != 42 {
		t.Fatal("handoff not typed")
	}
}

// Real local Unix transports and drain scheduling; engine actions are simulated.
// This intentionally does not impersonate a capless process or native factory.
func TestRoutedLaunchV3DrainWaitsForDispatchAndKeepsHelper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ids := Identities{APIUID: uint32(os.Geteuid()), APIGID: uint32(os.Getegid())}
	authority := &routedTransportAuthorityV3{entered: make(chan struct{}), release: make(chan struct{})}
	session, e := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	helper := &RoutedHelperRuntimeV3{ctx: ctx, session: session, identities: ids, metadata: Metadata{RunID: strings.Repeat("a", 32)}}
	base, guardian, _, _, _ := fixtureSessionV2(t)
	compat, e := NewRoutedCompatibilitySessionV2(base.base.run, base.base.namespace, base.base.engine, guardian, base.base.observe)
	if e != nil {
		t.Fatal(e)
	}
	var listeners [2]*net.UnixListener
	for i, name := range []string{"routed", "compat"} {
		l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), name), Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		listeners[i] = l
		defer l.Close()
	}
	b := routedLaunchBootstrapV3{Metadata: Metadata{RunID: strings.Repeat("a", 32)}, Identities: ids}
	active := startRoutedLaunchServersV3(ctx, listeners, helper, compat, b, int32(os.Getpid()))
	conn, e := net.DialUnix("unix", nil, listeners[0].Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	client, e := ConnectInheritedRoutedV3(ctx, conn, uint32(os.Geteuid()), uint32(os.Getegid()), int32(os.Getpid()), b.Metadata.RunID, 22)
	if e != nil {
		t.Fatal(e)
	}
	callDone := make(chan error, 1)
	go func() { _, e := client.Call(ctx, "observe", struct{}{}); callDone <- e }()
	select {
	case <-authority.entered:
	case <-time.After(time.Second):
		t.Fatal("dispatch not entered")
	}
	drained := make(chan struct{})
	go func() { active.drain(); close(drained) }()
	select {
	case <-drained:
		t.Fatal("replacement crossed in-flight call")
	case <-time.After(50 * time.Millisecond):
	}
	if ctx.Err() != nil {
		t.Fatal("API drain cancelled helper authority")
	}
	close(authority.release)
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not finish")
	}
	<-callDone
	_ = client.Close()
	// The same session/guardian, not a new helper, serves the next controller.
	next := startRoutedLaunchServersV3(ctx, listeners, helper, compat, b, int32(os.Getpid()))
	defer next.drain()
	conn, e = net.DialUnix("unix", nil, listeners[0].Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	client, e = ConnectInheritedRoutedV3(ctx, conn, uint32(os.Geteuid()), uint32(os.Getegid()), int32(os.Getpid()), b.Metadata.RunID, 22)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if _, e = client.Call(ctx, "observe", struct{}{}); e != nil {
		t.Fatal(e)
	}
	if authority.calls.Load() != 2 || session.epoch != 2 {
		t.Fatal("helper incarnation or epoch did not survive restart")
	}
}

func TestRoutedLaunchV3RejectsWrongControllerPID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, _ := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
	ids := Identities{APIUID: uint32(os.Geteuid()), APIGID: uint32(os.Getegid())}
	helper := &RoutedHelperRuntimeV3{ctx: ctx, session: session, identities: ids, metadata: Metadata{RunID: strings.Repeat("a", 32)}}
	base, guardian, _, _, _ := fixtureSessionV2(t)
	compat, _ := NewRoutedCompatibilitySessionV2(base.base.run, base.base.namespace, base.base.engine, guardian, base.base.observe)
	var listeners [2]*net.UnixListener
	for i := range listeners {
		l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "socket"), Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		listeners[i] = l
		defer l.Close()
	}
	b := routedLaunchBootstrapV3{Metadata: Metadata{RunID: strings.Repeat("a", 32)}, Identities: ids}
	active := startRoutedLaunchServersV3(ctx, listeners, helper, compat, b, int32(os.Getpid()+1))
	defer active.drain()
	conn, e := net.DialUnix("unix", nil, listeners[0].Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	if client, e := firewallipc.ConnectRoutedV3(ctx, conn, b.Metadata.RunID, 22); e == nil {
		_ = client.Close()
		t.Fatal("unassigned PID attached")
	}
	if session.epoch != 0 {
		t.Fatal("rejected process advanced epoch")
	}
}
func TestRoutedLaunchV3PIDBounds(t *testing.T) {
	for _, pid := range []int{-1, 0, 1, 1 << 32} {
		if _, err := routedLaunchPIDV3(pid); err == nil {
			t.Fatalf("invalid PID accepted: %d", pid)
		}
	}
	for _, pid := range []int{2, 2147483647} {
		actual, err := routedLaunchPIDV3(pid)
		if err != nil || int64(actual) != int64(pid) {
			t.Fatalf("valid PID changed: %d: %v", pid, err)
		}
	}
}
