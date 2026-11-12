//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func TestRoutedAPIV3RejectsUntrustedAssemblyWithoutStoreWrites(t *testing.T) {
	area := routedCoordinatorRoot(t)
	for _, ctx := range []context.Context{nil, context.Background()} {
		routed, rpeer := routedUnixPairV3(t)
		legacy, lpeer := routedUnixPairV3(t)
		if got, e := OpenRoutedOperationsRuntimeV3(ctx, Metadata{}, Identities{}, routed, legacy, int32(os.Getpid()), int32(os.Getpid()), OperationsRuntimeOptionsV2{Store: area}); e == nil || got != nil {
			t.Fatal("untrusted assembly admitted")
		}
		for _, peer := range []io.Reader{rpeer, lpeer} {
			b := make([]byte, 1)
			n, e := peer.Read(b)
			if n != 0 || e != io.EOF {
				t.Fatal("channel retained or command emitted", n, e)
			}
		}
		files, e := os.ReadDir(area.Name())
		if e != nil || len(files) != 0 {
			t.Fatal("failed assembly mutated store", files, e)
		}
	}
}

func TestRoutedAPIV3HandshakePrecedesLegacyAndStore(t *testing.T) {
	for _, mode := range []string{"wrong-routed-peer", "wrong-legacy-peer", "missing-reserve-profile"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			a, b := routedUnixPairV3(t)
			old, oldPeer := routedUnixPairV3(t)
			area := routedCoordinatorRoot(t)
			authority := &routedTransportAuthorityV3{}
			session, e := NewRoutedSessionV3(authority, routedTransportReaderV3{})
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- session.ServeRoutedV3(ctx, b, strings.Repeat("a", 32)) }()
			legacySeen := make(chan bool, 1)
			go func() {
				scan := bufio.NewScanner(oldPeer)
				if !scan.Scan() {
					legacySeen <- false
					return
				}
				legacySeen <- true
				hello, e := firewallipc.DecodeHelloV2(scan.Bytes(), false)
				if e != nil {
					return
				}
				hello.Run = strings.Repeat("a", 32)
				hello.Epoch = 1
				_ = json.NewEncoder(oldPeer).Encode(hello)
				_ = scan.Scan()
			}()
			rp, lp := int32(os.Getpid()), int32(os.Getpid())
			if mode == "wrong-routed-peer" {
				rp++
			}
			if mode == "wrong-legacy-peer" {
				lp++
			}
			ids := Identities{HelperUID: uint32(os.Geteuid()), IPCGID: uint32(os.Getegid())}
			m := Metadata{RunID: strings.Repeat("a", 32), GatewayNamespace: 22}
			r, e := connectRoutedOperationsV3(ctx, m, ids, a, old, rp, lp, authority.Identity(), OperationsRuntimeOptionsV2{Store: area})
			if e == nil || r != nil {
				t.Fatal("incomplete assembly admitted")
			}
			seen := <-legacySeen
			if seen != (mode == "missing-reserve-profile") {
				t.Fatal("legacy handshake occurred before v3 authorization", mode, seen)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("failed assembly retained routed controller")
			}
			files, e := os.ReadDir(area.Name())
			if e != nil || len(files) != 0 {
				t.Fatal("failure opened/wrote store", files, e)
			}
		})
	}
}

func TestRoutedAPIV3CloseLeavesEffectiveHelperPolicy(t *testing.T) {
	session, guardian, engine, previous, _ := fixtureSessionV2(t)
	compatibility := initializeV2(t, session, previous)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	routedSession, e := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	routed, done, e := routedTransportConnectV3(t, ctx, routedSession)
	if e != nil {
		t.Fatal(e)
	}
	runtime := &RoutedOperationsRuntimeV3{routed: routed, legacy: compatibility.client}
	if e = runtime.Close(); e != nil {
		t.Fatal(e)
	}
	compatibility.stop()
	<-done
	if engine.Current() != previous.Hash || guardian.Status().Phase != "idle" {
		t.Fatal("management close changed effective policy")
	}
	if _, e = routed.Call(ctx, "observe", struct{}{}); e == nil {
		t.Fatal("routed channel survived close")
	}
	if _, e = compatibility.client.Snapshot(ctx); e == nil {
		t.Fatal("compatibility channel survived close")
	}
	var empty *RoutedOperationsRuntimeV3
	if e = empty.Close(); e != nil {
		t.Fatal(e)
	}
}

var _ configpoc.RoutedAuthorityV1 = (*RoutedRemoteAuthority)(nil)

type apiRoutedIdentityV3 struct{ configpoc.RoutedAuthorityV1 }

func (*apiRoutedIdentityV3) Identity() networkexecutor.OwnedNamespaceIdentity {
	return networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Namespace: 42, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("b", 32)}
}
func TestRoutedAPIV3RejectsPoolProfileBeforeOpeningStore(t *testing.T) {
	legacySession, _, engine, previous, _ := fixtureSessionV2(t)
	compatibility := initializeV2(t, legacySession, previous)
	area := routedCoordinatorRoot(t)
	authority := &apiRoutedIdentityV3{}
	session, e := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a, b := routedUnixPairV3(t)
	done := make(chan error, 1)
	go func() { done <- session.ServeRoutedV3(ctx, b, strings.Repeat("b", 32)) }()
	client, e := firewallipc.ConnectRoutedV3(ctx, a, strings.Repeat("b", 32), 42)
	if e != nil {
		t.Fatal(e)
	}
	options := OperationsRuntimeOptionsV2{Store: area, Auth: &adminauth.Manager{}, Local: []configpoc.Engine{configpoc.NewSimEngine("local")}, Runtime: configpoc.RuntimeOptionsV2{GuardDeadlines: true, BootID: authority.Identity().BootID, SharedReader: &recoveryreserve.ReaderAccessV2{Version: 1}, Pools: configpoc.RuntimePoolsV2{Admission: &recoveryreserve.PoolV2{}, Plan: &recoveryreserve.PoolV2{}, Emergency: &recoveryreserve.PoolV2{}}}}
	got, e := assembleRoutedOperationsV3(ctx, client, compatibility.client, authority.Identity(), options)
	if !errors.Is(e, configpoc.ErrInvalid) || got != nil {
		t.Fatal("unopened pool profiles were accepted", e)
	}
	compatibility.stop()
	<-done
	if engine.Current() != previous.Hash {
		t.Fatal("profile failure changed effective policy")
	}
	files, e := os.ReadDir(area.Name())
	if e != nil || len(files) != 0 {
		t.Fatal("profile failure opened store", files, e)
	}
}

func TestRoutedAPIV3RejectsDuplicatedSocketDescriptors(t *testing.T) {
	a, b := routedUnixPairV3(t)
	if !distinctRoutedChannelsV3(a, b) {
		t.Fatal("distinct sockets rejected")
	}
	f, e := a.File()
	if e != nil {
		t.Fatal(e)
	}
	conn, e := net.FileConn(f)
	_ = f.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	alias, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("not Unix")
	}
	if distinctRoutedChannelsV3(a, alias) {
		t.Fatal("duplicated descriptor accepted")
	}
}
