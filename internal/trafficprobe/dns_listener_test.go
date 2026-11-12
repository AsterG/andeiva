package trafficprobe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

const dnsListenerAttempts = 32

// A port allocated for one protocol may be reserved for another on Windows.
func listenDNSPair(packet func(string, string) (net.PacketConn, error), stream func(string, string) (net.Listener, error)) (net.Listener, net.PacketConn, error) {
	var last error
	for range dnsListenerAttempts {
		udp, err := packet("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		tcp, err := stream("tcp4", udp.LocalAddr().String())
		if err == nil {
			return tcp, udp, nil
		}
		last = err
		if err := udp.Close(); err != nil {
			return nil, nil, errors.Join(last, err)
		}
	}
	return nil, nil, fmt.Errorf("DNS listener pair exhausted after %d attempts: %w", dnsListenerAttempts, last)
}

func TestDNSListenerPairRetriesAndCloses(t *testing.T) {
	for _, always := range []bool{false, true} {
		t.Run(fmt.Sprintf("always-refuse=%t", always), func(t *testing.T) {
			var discarded []net.PacketConn
			attempts := 0
			tcp, udp, err := listenDNSPair(func(network, address string) (net.PacketConn, error) {
				conn, err := net.ListenPacket(network, address)
				if err == nil {
					discarded = append(discarded, conn)
				}
				return conn, err
			}, func(network, address string) (net.Listener, error) {
				attempts++
				if always || attempts == 1 {
					return nil, os.ErrPermission
				}
				return net.Listen(network, address)
			})
			if always {
				if !errors.Is(err, os.ErrPermission) || attempts != dnsListenerAttempts || tcp != nil || udp != nil {
					t.Fatalf("unbounded or wrong failure: attempts=%d, err=%v", attempts, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer tcp.Close()
				defer udp.Close()
				if tcp.Addr().String() != udp.LocalAddr().String() || attempts < 2 {
					t.Fatal("listeners must share the successfully reserved endpoint")
				}
				discarded = discarded[:len(discarded)-1]
			}
			for _, conn := range discarded {
				_ = conn.SetReadDeadline(time.Now())
				if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("discarded listener remains open: %v", err)
				}
			}
		})
	}
}
