// Package nftfixture provides a disposable, isolated network experiment fixture.
package nftfixture

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const SourceIP = "198.18.0.2"
const SinkIP = "198.18.0.6"
const probeTimeout = 300 * time.Millisecond

func validProbe(protocol string, port int) bool {
	return (protocol == "tcp" || protocol == "udp") && port >= 18080 && port <= 18082
}

// HandleRole runs only the fixed fixture subprocess roles. It must be called
// before parsing the ordinary command flags. A probe exits 10 for no response;
// malformed requests and local failures use a different exit status.
func HandleRole(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "--nft-fixture" {
		return false, 0
	}
	if len(args) == 2 && args[1] == "keeper" {
		_, err := io.Copy(io.Discard, os.Stdin)
		if err != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 3 && args[1] == "forward" {
		host, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil || enableForwarding(host) != nil {
			return true, 2
		}
		return true, 0
	}
	if len(args) == 3 && (args[1] == "listen" || args[1] == "listen-source") {
		host, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			return true, 2
		}
		if err := armParentDeath(host); err != nil {
			return true, 1
		}
		address := SinkIP
		if args[1] == "listen-source" {
			address = SourceIP
		}
		if err := listenAt(address); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		return true, 0
	}
	if len(args) == 5 && (args[1] == "probe" || args[1] == "probe-source") {
		port, err := strconv.Atoi(args[3])
		if err != nil || !validProbe(args[2], port) {
			return true, 2
		}
		host, err := strconv.ParseUint(args[4], 10, 64)
		if err != nil {
			return true, 2
		}
		if err := armParentDeath(host); err != nil {
			return true, 1
		}
		address := SinkIP
		if args[1] == "probe-source" {
			address = SourceIP
		}
		ok, err := probeAt(args[2], port, address)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		if !ok {
			return true, 10
		}
		return true, 0
	}
	return true, 2
}

func listen() error { return listenAt(SinkIP) }
func listenAt(ip string) error {
	if ip != SourceIP && ip != SinkIP {
		return errors.New("ANDEIVA_NFT_PROBE_INVALID")
	}
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	for port := 18080; port <= 18082; port++ {
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		closers = append(closers, tcp)
		go func() {
			for {
				conn, err := tcp.Accept()
				if err != nil {
					return
				}
				// The bounded fixture has one sequential request per socket.
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var payload [64]byte
				n, readErr := io.ReadFull(conn, payload[:])
				if readErr == nil {
					_, _ = conn.Write(payload[:n])
				}
				_ = conn.Close()
			}
		}()
		udp, err := net.ListenPacket("udp4", address)
		if err != nil {
			return err
		}
		closers = append(closers, udp)
		go func() {
			var payload [64]byte
			for {
				n, peer, err := udp.ReadFrom(payload[:])
				if err != nil {
					return
				}
				if n == len(payload) {
					_, _ = udp.WriteTo(payload[:n], peer)
				}
			}
		}()
	}
	if _, err := fmt.Fprintln(os.Stdout, "ANDEIVA_NFT_LISTEN_READY"); err != nil {
		return err
	}
	_, err := io.Copy(io.Discard, os.Stdin)
	return err
}

func probe(protocol string, port int) (bool, error) {
	return probeAt(protocol, port, SinkIP)
}
func probeAt(protocol string, port int, ip string) (bool, error) {
	if !validProbe(protocol, port) || (ip != SourceIP && ip != SinkIP) {
		return false, errors.New("ANDEIVA_NFT_PROBE_INVALID")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, err
	}
	payload := []byte(hex.EncodeToString(random[:]))
	conn, err := net.DialTimeout(protocol+"4", net.JoinHostPort(ip, strconv.Itoa(port)), probeTimeout)
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return false, nil
		}
		return false, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return false, err
	}
	if _, err := conn.Write(payload); err != nil {
		return false, err
	}
	answer := make([]byte, len(payload))
	_, err = io.ReadFull(conn, answer)
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return false, nil
		}
		return false, err
	}
	if !bytes.Equal(payload, answer) {
		return false, errors.New("ANDEIVA_NFT_PROBE_NONCE_MISMATCH")
	}
	return true, nil
}
