package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func routedClientServerV3(t *testing.T, serve func(net.Conn, *bufio.Scanner, RoutedHelloV3)) (*RoutedClientV3, <-chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		scan := bufio.NewScanner(b)
		scan.Buffer(make([]byte, 4096), LocalReplyMaxFrame)
		if !scan.Scan() {
			return
		}
		h, e := DecodeRoutedHelloV3(scan.Bytes(), false)
		if e != nil {
			return
		}
		h.Run = strings.Repeat("b", 32)
		h.Epoch = 4
		if json.NewEncoder(b).Encode(h) != nil {
			return
		}
		serve(b, scan, h)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, e := ConnectRoutedV3(ctx, a, strings.Repeat("a", 32), 22)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}
func TestRoutedClientV3ObservedCorrelationAndErrors(t *testing.T) {
	client, done := routedClientServerV3(t, func(conn net.Conn, scan *bufio.Scanner, h RoutedHelloV3) {
		last := h.Epoch << 32
		for i := 0; i < 2; i++ {
			if !scan.Scan() {
				return
			}
			request, _, e := DecodeRoutedRequestV3(scan.Bytes(), h.Run, 22, last)
			if e != nil {
				t.Error(e)
				return
			}
			last = request.Sequence
			payload := json.RawMessage(`{"receipt":{"phase":"bootstrap","id":"","previous":"","target":"","deadline":"0001-01-01T00:00:00Z"},"revision":""}`)
			reply := RoutedReplyV3{RoutedProtocolV3, h.Run, last, 22, "routed", request.Verb, "", payload}
			if i == 1 {
				reply.Error = "ANDEIVA_CONFIG_RECOVERY_REQUIRED"
				reply.Payload = json.RawMessage(`{}`)
			}
			if json.NewEncoder(conn).Encode(reply) != nil {
				return
			}
		}
	})
	value, e := client.Call(context.Background(), "observe", struct{}{})
	if e != nil || value.Observed.Receipt.Phase != "bootstrap" {
		t.Fatal(e)
	}
	if _, e = client.Call(context.Background(), "observe", struct{}{}); e == nil || e.Error() != "ANDEIVA_CONFIG_RECOVERY_REQUIRED" {
		t.Fatal("missing explicit recovery error", e)
	}
	<-done
}
func TestRoutedClientV3LostReplyClosesWithoutReplay(t *testing.T) {
	seen := make(chan struct{}, 1)
	client, done := routedClientServerV3(t, func(conn net.Conn, scan *bufio.Scanner, h RoutedHelloV3) {
		if !scan.Scan() {
			return
		}
		seen <- struct{}{}
		if scan.Scan() {
			t.Error("request replayed after lost reply")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e := client.Call(ctx, "observe", struct{}{}); e == nil {
		t.Fatal("lost reply succeeded")
	}
	<-seen
	if _, e := client.Call(context.Background(), "observe", struct{}{}); e == nil {
		t.Fatal("dead channel reused")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("channel did not close")
	}
}
func TestRoutedReplyV3RejectsWrongEnvelopeAndPrivateDiagnostics(t *testing.T) {
	data := routedWireV3(t, "observe", struct{}{})
	request, _, e := DecodeRoutedRequestV3(data, strings.Repeat("a", 32), 22, 6)
	if e != nil {
		t.Fatal(e)
	}
	reply := RoutedReplyV3{RoutedProtocolV3, request.Run, 7, 22, "routed", "observe", "ANDEIVA_CONFIG_RECOVERY_REQUIRED", json.RawMessage(`{}`)}
	valid, _ := json.Marshal(reply)
	if _, _, e = DecodeRoutedReplyV3(valid, request); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*RoutedReplyV3){func(r *RoutedReplyV3) { r.ProtocolVersion = 2 }, func(r *RoutedReplyV3) { r.Sequence++ }, func(r *RoutedReplyV3) { r.Namespace++ }, func(r *RoutedReplyV3) { r.Verb = "apply" }, func(r *RoutedReplyV3) { r.Error = "raw kernel detail" }, func(r *RoutedReplyV3) { r.Payload = json.RawMessage(`{"kernel":"private"}`) }} {
		bad := reply
		change(&bad)
		wire, _ := json.Marshal(bad)
		if _, _, e = DecodeRoutedReplyV3(wire, request); e == nil {
			t.Fatal("accepted mismatched/private reply")
		}
	}
}
