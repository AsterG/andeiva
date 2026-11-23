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

func TestRoutedDHCPWaitingV1CodecRejectsOtherMeanings(t *testing.T) {
	testRoutedDHCPPendingCodecV1(t, ErrRoutedDHCPWaitingV1)
}
func TestRoutedDHCPNoLeaseV1CodecRejectsOtherMeanings(t *testing.T) {
	testRoutedDHCPPendingCodecV1(t, ErrRoutedDHCPNoLeaseV1)
}
func testRoutedDHCPPendingCodecV1(t *testing.T, pending error) {
	for _, kind := range []string{"valid", "wrong-verb", "unknown-version", "grant-payload", "replay"} {
		t.Run(kind, func(t *testing.T) {
			q := RoutedRequestV3{RoutedProtocolV3, strings.Repeat("a", 32), 7, 22, "routed", "dhcp_begin", json.RawMessage(`{}`)}
			if kind == "wrong-verb" {
				q.Verb = "dhcp_current"
			}
			r := RoutedReplyV3{RoutedProtocolV3, q.Run, q.Sequence, q.Namespace, "routed", q.Verb, pending.Error(), json.RawMessage(`{}`)}
			switch kind {
			case "unknown-version":
				r.Error = strings.TrimSuffix(pending.Error(), "1") + "2"
			case "grant-payload":
				r.Payload = json.RawMessage(`{"epoch":"1"}`)
			case "replay":
				r.Sequence--
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			_, out, err := DecodeRoutedReplyV3(raw, q)
			if (err == nil) != (kind == "valid") || out.DHCP.Epoch != 0 {
				t.Fatal("waiting codec", kind, err)
			}
		})
	}
}

func TestRoutedDHCPWaitingV1ClientPreservesOnlyQualifiedFlags(t *testing.T) {
	testRoutedDHCPPendingClientV1(t, ErrRoutedDHCPWaitingV1)
}
func TestRoutedDHCPNoLeaseV1ClientPreservesOnlyQualifiedFlags(t *testing.T) {
	testRoutedDHCPPendingClientV1(t, ErrRoutedDHCPNoLeaseV1)
}
func testRoutedDHCPPendingClientV1(t *testing.T, pending error) {
	for _, kind := range []string{"qualified", "unqualified", "recovery", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				scan := bufio.NewScanner(b)
				if !scan.Scan() {
					return
				}
				h, err := DecodeRoutedHelloV3(scan.Bytes(), false)
				if err != nil {
					return
				}
				h.Run = h.RuntimeRun
				h.Epoch = 1
				if json.NewEncoder(b).Encode(h) != nil || !scan.Scan() {
					return
				}
				q, _, err := DecodeRoutedRequestV3(scan.Bytes(), h.Run, h.Namespace, h.Epoch<<32)
				if err != nil {
					return
				}
				code := pending.Error()
				if kind == "recovery" {
					code = "ANDEIVA_CONFIG_RECOVERY_REQUIRED"
				}
				if kind == "cancel" {
					cancel()
				}
				_ = json.NewEncoder(b).Encode(RoutedReplyV3{RoutedProtocolV3, q.Run, q.Sequence, q.Namespace, "routed", q.Verb, code, json.RawMessage(`{}`)})
			}()
			c, err := ConnectRoutedDHCPV3(ctx, a, strings.Repeat("a", 32), 22)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			qualified := kind != "unqualified"
			c.publicationAllowed.Store(qualified)
			c.closingAllowed.Store(qualified)
			result, err := c.Call(ctx, "dhcp_begin", RoutedDHCPRequestV3{})
			if err == nil || result.DHCP.Epoch != 0 {
				t.Fatal("waiting returned a grant")
			}
			expected := kind == "qualified"
			if c.IntegrityPublicationAllowedV1() != expected || c.IntegrityClosingAllowedV1() != expected {
				t.Fatal("wrong integrity transition", kind, err)
			}
			if kind == "qualified" || kind == "unqualified" {
				if err != pending {
					t.Fatal("missing typed waiting", err)
				}
			} else if err == pending {
				t.Fatal("failure became waiting")
			}
			<-done
		})
	}
}
