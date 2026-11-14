package trafficprobe

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

const dnsListenerAttempts = 32

// TCP and UDP allocators can each return contiguous ranges that the other
// protocol refuses. Try one random candidate per disjoint unprivileged band,
// retaining both real listeners only after the same endpoint accepts both.
func listenDNSPair(packet func(string, string) (net.PacketConn, error), stream func(string, string) (net.Listener, error)) (net.Listener, net.PacketConn, error) {
	var last error
	const firstPort = 1024
	const bandSize = (65536 - firstPort) / dnsListenerAttempts
	start := rand.IntN(dnsListenerAttempts)
	for attempt := range dnsListenerAttempts {
		port := firstPort + ((start+attempt)%dnsListenerAttempts)*bandSize + rand.IntN(bandSize)
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		tcp, err := stream("tcp4", address)
		if err != nil {
			last = err
			continue
		}
		udp, err := packet("udp4", tcp.Addr().String())
		if err == nil {
			return tcp, udp, nil
		}
		last = err
		if err := tcp.Close(); err != nil {
			return nil, nil, errors.Join(last, err)
		}
	}
	return nil, nil, fmt.Errorf("DNS listener pair exhausted after %d attempts: %w", dnsListenerAttempts, last)
}

func TestDNSListenerPairRetriesAndCloses(t *testing.T) {
	for _, always := range []bool{false, true} {
		t.Run(fmt.Sprintf("always-refuse=%t", always), func(t *testing.T) {
			var discarded []net.Listener
			attempts, tcpAttempts := 0, 0
			var last error
			tcp, udp, err := listenDNSPair(func(network, address string) (net.PacketConn, error) {
				attempts++
				if always || attempts == 1 {
					last = os.ErrPermission
					return nil, os.ErrPermission
				}
				conn, err := net.ListenPacket(network, address)
				last = err
				return conn, err
			}, func(network, address string) (net.Listener, error) {
				tcpAttempts++
				host, port, err := net.SplitHostPort(address)
				value, parseErr := strconv.Atoi(port)
				if err != nil || parseErr != nil || host != "127.0.0.1" || value < 1024 || value > 65535 {
					t.Fatal("invalid loopback candidate", address)
				}
				conn, err := net.Listen(network, address)
				last = err
				if err == nil {
					discarded = append(discarded, conn)
					t.Cleanup(func() { _ = conn.Close() })
				}
				return conn, err
			})
			if always {
				if last == nil || !errors.Is(err, last) || tcpAttempts != dnsListenerAttempts || tcp != nil || udp != nil {
					t.Fatalf("unbounded or wrong failure: attempts=%d, err=%v", tcpAttempts, err)
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
				if endpoint, ok := conn.(*net.TCPListener); ok {
					_ = endpoint.SetDeadline(time.Now())
				}
				if _, err := conn.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("discarded listener remains open: %v", err)
				}
			}
		})
	}
}

func TestDNSListenerPairAllTCPAllocationsFail(t *testing.T) {
	ports := map[int]bool{}
	bands := map[int]bool{}
	tcp, udp, err := listenDNSPair(func(string, string) (net.PacketConn, error) {
		t.Fatal("UDP allocation after TCP allocation failed")
		return nil, nil
	}, func(network, address string) (net.Listener, error) {
		host, port, splitErr := net.SplitHostPort(address)
		value, parseErr := strconv.Atoi(port)
		if splitErr != nil || parseErr != nil || host != "127.0.0.1" || network != "tcp4" || value < 1024 || value > 65535 || ports[value] {
			t.Fatal("invalid or repeated candidate", address)
		}
		ports[value], bands[(value-1024)/2016] = true, true
		return nil, os.ErrPermission
	})
	if tcp != nil || udp != nil || !errors.Is(err, os.ErrPermission) || len(ports) != dnsListenerAttempts || len(bands) != dnsListenerAttempts {
		t.Fatalf("unexpected first allocation result: %v", err)
	}
}

type dnsCloseErrorListener struct {
	net.Listener
	err error
}

func (l dnsCloseErrorListener) Close() error {
	return errors.Join(l.Listener.Close(), l.err)
}

func TestDNSListenerPairCloseFailureStopsRetries(t *testing.T) {
	closeErr := errors.New("test listener close failure")
	var held net.Listener
	udpCalls := 0
	tcp, udp, err := listenDNSPair(func(string, string) (net.PacketConn, error) {
		udpCalls++
		return nil, os.ErrPermission
	}, func(network, address string) (net.Listener, error) {
		conn, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		held = conn
		return dnsCloseErrorListener{Listener: conn, err: closeErr}, nil
	})
	if held == nil {
		t.Fatal("no TCP listener acquired", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	if tcp != nil || udp != nil || udpCalls != 1 || !errors.Is(err, os.ErrPermission) || !errors.Is(err, closeErr) {
		t.Fatal("cleanup error lost or retried", err)
	}
	if endpoint, ok := held.(*net.TCPListener); ok {
		_ = endpoint.SetDeadline(time.Now())
	}
	if _, err := held.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("listener left open", err)
	}
}
