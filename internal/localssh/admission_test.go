package localssh

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"golang.org/x/crypto/ssh"
)

func TestSSHVerifiedLoginDoesNotUseAnonymousAllowance(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	for i := 0; i < 4; i++ {
		if _, _, err := h.auth.LoginFrom(netip.MustParseAddr("198.18.0.1"), "operator", "invalid"); !errors.Is(err, adminauth.ErrDenied) {
			t.Fatal(err)
		}
	}
	client := h.client(t)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { login, logout := h.audit.counts(); return login == 1 && logout == 1 })
}

type peerAddress string

func (p peerAddress) Network() string { return "tcp" }
func (p peerAddress) String() string  { return string(p) }

type peerListener struct {
	net.Listener
	peer net.Addr
}

func (l peerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return peerConnection{c, l.peer}, nil
}

type peerConnection struct {
	net.Conn
	peer net.Addr
}

func (c peerConnection) RemoteAddr() net.Addr { return c.peer }

// The injected connection metadata is invalid while the SSH byte transport is
// real. A correct username and credential cannot replace the transport peer.
func TestSSHInvalidConnectionPeerCannotAuthenticate(t *testing.T) {
	for _, test := range []struct {
		name string
		peer net.Addr
	}{
		{"missing-peer", nil},
		{"malformed-address", peerAddress("not-an-address")},
		{"scoped-ipv6", peerAddress("[fe80::1%src0]:1234")},
		{"multicast-ipv4", peerAddress("224.0.0.1:1234")},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t, "admin", nil, func(listener net.Listener, _ *testAudit) net.Listener { return peerListener{listener, test.peer} })
			client, err := ssh.Dial("tcp", h.address, h.config())
			if err == nil {
				_ = client.Close()
				t.Fatal("credential replaced an invalid connection peer")
			}
			if login, _ := h.audit.counts(); login != 0 || h.backend.count() != 0 {
				t.Fatal("invalid connection peer reached administrative state")
			}
		})
	}
}
