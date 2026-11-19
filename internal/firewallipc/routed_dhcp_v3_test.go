package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestRoutedDHCPV3RequiresCapabilityAndRejectsAuthorityFields(t *testing.T) {
	h := NewRoutedHelloV3(strings.Repeat("a", 32), 22)
	h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3, RoutedDHCPCapabilityV3)
	b, _ := json.Marshal(h)
	if _, err := DecodeRoutedHelloV3(b, false); err != nil {
		t.Fatal(err)
	}
	h.RequiredFeatures[3], h.RequiredFeatures[5] = h.RequiredFeatures[5], h.RequiredFeatures[3]
	b, _ = json.Marshal(h)
	if _, err := DecodeRoutedHelloV3(b, false); err == nil {
		t.Fatal("capability reorder accepted")
	}
	for _, verb := range []string{"dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_live"} {
		p := map[string]any{"work": strings.Repeat("b", 64)}
		wire := routedWireV3(t, verb, p)
		if _, _, err := DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 6); err != nil {
			t.Fatal(verb, err)
		}
		for _, field := range []string{"owner", "owner_pid", "start_ticks", "epoch", "deadline_boot_ns", "route", "command", "namespace", "valid"} {
			p[field] = 1
			if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, p), strings.Repeat("a", 32), 22, 6); err == nil {
				t.Fatal("authority field accepted", verb, field)
			}
			delete(p, field)
		}
		if _, _, err := DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 7); err == nil {
			t.Fatal("replay")
		}
	}
	for _, verb := range []string{"dhcp_begin", "dhcp_current", "dhcp_retire"} {
		if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, struct{}{}), strings.Repeat("a", 32), 22, 6); err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, map[string]bool{"valid": true}), strings.Repeat("a", 32), 22, 6); err == nil {
			t.Fatal("caller proof")
		}
	}
}

func TestRoutedDHCPSameEffectiveRenewalRequiresNegotiatedCapability(t *testing.T) {
	run, work, snapshot := strings.Repeat("a", 32), strings.Repeat("b", 64), strings.Repeat("c", 64)
	for _, renewal := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "v4"}[renewal], func(t *testing.T) {
			a, b := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			seen := make(chan string, 1)
			go func() {
				defer b.Close()
				scan := bufio.NewScanner(b)
				if !scan.Scan() {
					return
				}
				hello, err := DecodeRoutedHelloV3(scan.Bytes(), false)
				if err != nil || hello.HasCapability(RoutedDHCPRenewalCapabilityV4) != renewal {
					return
				}
				hello.Run, hello.Epoch = run, 1
				if json.NewEncoder(b).Encode(hello) != nil || !scan.Scan() {
					return
				}
				request, _, err := DecodeRoutedRequestV3(scan.Bytes(), run, 22, 1<<32)
				if err != nil {
					return
				}
				seen <- request.Verb
				_ = json.NewEncoder(b).Encode(RoutedReplyV3{RoutedProtocolV3, run, request.Sequence, 22, "routed", request.Verb, "ANDEIVA_CONFIG_RECOVERY_REQUIRED", json.RawMessage(`{}`)})
			}()
			var client *RoutedClientV3
			var err error
			if renewal {
				client, err = ConnectRoutedDHCPRenewalV4(ctx, a, run, 22, false, false)
			} else {
				client, err = ConnectRoutedDHCPV3(ctx, a, run, 22)
			}
			if err != nil {
				t.Fatal("handshake", err)
			}
			defer client.Close()
			if client.DHCPRenewalEnabledV4() != renewal {
				t.Fatal("profile mismatch")
			}
			_, err = client.Call(ctx, "dhcp_renew", RoutedDHCPRequestV3{Work: work, Snapshot: snapshot})
			if renewal {
				if err == nil || err.Error() != "ANDEIVA_CONFIG_RECOVERY_REQUIRED" {
					t.Fatal("renewal reply", err)
				}
				if got := <-seen; got != "dhcp_renew" {
					t.Fatal("wrong request", got)
				}
			} else if err == nil || err != ErrChannel {
				t.Fatal("legacy profile accepted renewal", err)
			}
		})
	}
}

func TestRoutedDHCPSameEffectiveRenewalDeadlineNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, verb                          string
		renewal                             bool
		delay, caller, cancelAfter, elapsed time.Duration
		ok                                  bool
	}{
		{"legacy", "dhcp_open", false, 4 * time.Second, 0, 0, 3 * time.Second, false},
		{"v4", "dhcp_open", true, 4 * time.Second, 0, 0, 4 * time.Second, true},
		{"v4-limit", "dhcp_open", true, 11 * time.Second, 0, 0, 10 * time.Second, false},
		{"short-caller", "dhcp_open", true, 4 * time.Second, time.Second, 0, time.Second, false},
		{"cancelled", "dhcp_open", true, 4 * time.Second, 0, time.Second, time.Second, false},
		{"v4-read", "dhcp_live", true, 4 * time.Second, 0, 0, 3 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				run := strings.Repeat("a", 32)
				peerDone := make(chan struct{})
				defer func() { _ = a.Close(); _ = b.Close(); <-peerDone }()
				go func() {
					defer close(peerDone)
					defer b.Close()
					scan := bufio.NewScanner(b)
					if !scan.Scan() {
						return
					}
					hello, err := DecodeRoutedHelloV3(scan.Bytes(), false)
					if err != nil {
						return
					}
					hello.Run, hello.Epoch = run, 1
					if json.NewEncoder(b).Encode(hello) != nil || !scan.Scan() {
						return
					}
					request, _, err := DecodeRoutedRequestV3(scan.Bytes(), run, 22, 1<<32)
					if err != nil {
						return
					}
					time.Sleep(tc.delay)
					_ = json.NewEncoder(b).Encode(RoutedReplyV3{RoutedProtocolV3, run, request.Sequence, 22, "routed", request.Verb, "", json.RawMessage(`{}`)})
				}()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var client *RoutedClientV3
				var err error
				if tc.renewal {
					client, err = ConnectRoutedDHCPRenewalV4(ctx, a, run, 22, false, false)
				} else {
					client, err = ConnectRoutedDHCPV3(ctx, a, run, 22)
				}
				if err != nil {
					t.Fatal("handshake", err)
				}
				defer client.Close()
				callCtx := ctx
				if tc.caller != 0 {
					var stop context.CancelFunc
					callCtx, stop = context.WithTimeout(ctx, tc.caller)
					defer stop()
				}
				if tc.cancelAfter != 0 {
					go func() { time.Sleep(tc.cancelAfter); cancel() }()
				}
				started := time.Now()
				_, err = client.Call(callCtx, tc.verb, RoutedDHCPRequestV3{Work: strings.Repeat("b", 64)})
				if (err == nil) != tc.ok || time.Since(started) != tc.elapsed {
					t.Fatalf("result=%v elapsed=%v expected=%v", err, time.Since(started), tc.elapsed)
				}
				if !tc.ok && !client.dead {
					t.Fatal("timeout/cancellation kept a qualified channel")
				}
				<-peerDone
			})
		})
	}
}
