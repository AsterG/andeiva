//go:build linux

package localruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/adminclient"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type ProbeRequest struct {
	Side        string                   `json:"side"`
	Family      string                   `json:"family"`
	Origin      string                   `json:"origin"`
	Protocol    string                   `json:"protocol"`
	Port        uint16                   `json:"port"`
	Operation   string                   `json:"operation"`
	Username    string                   `json:"username"`
	Session     string                   `json:"session,omitempty"`
	Proof       *localadmin.ProofRequest `json:"proof,omitempty"`
	Transaction *localadmin.Request      `json:"transaction,omitempty"`
}
type ProbeResult struct {
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}
type probeLaunch struct {
	Request ProbeRequest `json:"request"`
	CA      []byte       `json:"ca"`
	HostKey []byte       `json:"host_key"`
}

func (p ProbeRequest) validate() error {
	if (p.Side != "source" && p.Side != "sink") || (p.Family != "ipv4" && p.Family != "ipv6") || (p.Origin != "primary" && p.Origin != "alternate") || (p.Protocol != "https" && p.Protocol != "ssh") || p.Port < 1024 || (p.Username != "admin-a" && p.Username != "admin-b" && p.Username != "viewer") {
		return ErrUnavailable
	}
	if p.Session != "" {
		b, e := hex.DecodeString(p.Session)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != p.Session {
			return ErrUnavailable
		}
	}
	switch p.Operation {
	case "status", "effective":
		if p.Proof != nil || p.Transaction != nil {
			return ErrUnavailable
		}
	case "proof":
		if p.Proof == nil || p.Transaction != nil {
			return ErrUnavailable
		}
	case "execute":
		if p.Transaction == nil || p.Proof != nil {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}
func (p ProbeRequest) addresses() (string, string, string, error) {
	if p.validate() != nil {
		return "", "", "", ErrUnavailable
	}
	iface := "src0"
	if p.Side == "sink" {
		iface = "dst0"
	}
	for _, i := range nftfixture.LocalInventory() {
		if i.Name != iface {
			continue
		}
		for _, a := range i.Addresses {
			ip, e := netip.ParseAddr(a)
			if e != nil || ip.IsLinkLocalUnicast() || ip.Is4() != (p.Family == "ipv4") {
				continue
			}
			source := ip.Next()
			if p.Origin == "alternate" {
				source = source.Next()
			}
			network := "tcp4"
			if !ip.Is4() {
				network = "tcp6"
			}
			return source.String(), net.JoinHostPort(a, strconv.Itoa(int(p.Port))), network, nil
		}
	}
	return "", "", "", ErrUnavailable
}

type probeError string

func (e probeError) Error() string { return string(e) }

const probeTimeout probeError = "ANDEIVA_PROBE_TIMEOUT"
const probeRefused probeError = "ANDEIVA_PROBE_REFUSED"
const probeTLS probeError = "ANDEIVA_PROBE_TLS"
const probeHostKey probeError = "ANDEIVA_PROBE_HOSTKEY"
const probeAuth probeError = "ANDEIVA_PROBE_AUTH"
const probeProtocol probeError = "ANDEIVA_PROBE_PROTOCOL"

func dialError(e error) error {
	if errors.Is(e, unix.ECONNREFUSED) {
		return probeRefused
	}
	var n net.Error
	if errors.As(e, &n) && n.Timeout() {
		return probeTimeout
	}
	return probeProtocol
}
func resultError(e error) ProbeResult {
	var p probeError
	if errors.As(e, &p) {
		return ProbeResult{Error: p.Error()}
	}
	return ProbeResult{Error: probeProtocol.Error()}
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxBootstrap {
		b.overflow = true
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
func (s *supervisor) probe(ctx context.Context, p ProbeRequest) (result ProbeResult) {
	if p.validate() != nil {
		return resultError(probeProtocol)
	}
	ca, e := readFile(s.dir, "ca.crt", 0, s.ids.APIGID, 0440, 8192)
	if e != nil {
		return resultError(probeTLS)
	}
	host, e := readFile(s.dir, "host.pub", 0, s.ids.APIGID, 0440, 4096)
	if e != nil {
		return resultError(probeHostKey)
	}
	if p.Session == "" {
		data, e := readFile(s.dir+"/operator", p.Username+".json", 0, 0, 0600, 4096)
		var credential adminclient.Credentials
		if e != nil || firewallipc.Decode(data, &credential) != nil {
			return resultError(probeAuth)
		}
		token, revoke, e := recoverySession(ctx, "https://127.0.0.1:"+strconv.Itoa(RecoveryPort), ca, credential)
		clear(data)
		if e != nil {
			return resultError(e)
		}
		p.Session = token
		defer func() {
			if revoke() != nil {
				result = resultError(probeAuth)
			}
		}()
	}
	// Only an ephemeral or explicitly borrowed session reaches the probe UID.
	input := encode(probeLaunch{p, ca, host})
	if len(input) > maxBootstrap {
		return resultError(probeProtocol)
	}
	r, w, e := os.Pipe()
	if e != nil {
		return resultError(probeProtocol)
	}
	defer r.Close()
	defer w.Close()
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var output boundedOutput
	cmd, e := s.active.fixture.LaunchLocalProbe(bounded, p.Side, r, &output, io.Discard)
	if e != nil {
		return resultError(probeProtocol)
	}
	if r.Close() != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return resultError(probeProtocol)
	}
	written := make(chan error, 1)
	go func() { _, e := w.Write(input); written <- errors.Join(e, w.Close()) }()
	e = cmd.Wait()
	we := <-written
	if e != nil || we != nil || output.overflow {
		return resultError(probeProtocol)
	}
	var reply ProbeResult
	if firewallipc.Decode(output.Bytes(), &reply) != nil {
		return resultError(probeProtocol)
	}
	return reply
}

func probeProcess(ctx context.Context, host uint64, parent int, side string, out io.Writer) error {
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 || uint64(uid) > 2147483647 || uint64(gid) > 2147483647 {
		return ErrUnavailable
	}
	if nftfixture.GuardLocalProbe(host, parent, uint32(uid), uint32(gid), side) != nil {
		return ErrUnavailable
	}
	var p probeLaunch
	if readBootstrap(4, &p) != nil || p.Request.validate() != nil || p.Request.Side != side || p.Request.Session == "" {
		return ErrUnavailable
	}
	source, target, network, e := p.Request.addresses()
	if e != nil {
		return e
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var result ProbeResult
	if p.Request.Protocol == "https" {
		result = probeHTTPS(bounded, p, dialer, network, target)
	} else {
		result = probeSSH(bounded, p, dialer, network, target)
	}
	return json.NewEncoder(out).Encode(result)
}

func probeHTTPS(ctx context.Context, p probeLaunch, dialer *net.Dialer, network, target string) ProbeResult {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CA) {
		return resultError(probeTLS)
	}
	host, _, e := net.SplitHostPort(target)
	if e != nil {
		return resultError(probeProtocol)
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: 8 * time.Second, DialTLSContext: func(c context.Context, _, _ string) (net.Conn, error) {
		raw, e := dialer.DialContext(c, network, target)
		if e != nil {
			return nil, dialError(e)
		}
		secure := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: host})
		handshake, cancel := context.WithTimeout(c, 3*time.Second)
		defer cancel()
		if secure.HandshakeContext(handshake) != nil {
			_ = raw.Close()
			return nil, probeTLS
		}
		return secure, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return probeProtocol }}
	call := func(method, path string, body any, token string) ProbeResult {
		var input io.Reader
		if body != nil {
			input = bytes.NewReader(encode(body))
		}
		r, e := http.NewRequestWithContext(ctx, method, "https://"+target+path, input)
		if e != nil {
			return resultError(probeProtocol)
		}
		r.Header.Set("X-ANDEIVA-Client", "api")
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := client.Do(r)
		if e != nil {
			return resultError(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, 60<<10+1))
		if e != nil || len(data) > 60<<10 || !json.Valid(data) {
			return resultError(probeProtocol)
		}
		result := ProbeResult{Status: response.StatusCode, Data: data}
		if response.StatusCode == 401 || response.StatusCode == 403 {
			result.Error = probeAuth.Error()
		}
		return result
	}
	token := p.Request.Session
	if token == "" {
		return resultError(probeAuth)
	}
	switch p.Request.Operation {
	case "status":
		return call("GET", "/api/v1/local-services", nil, token)
	case "effective":
		return call("GET", "/api/v1/effective-policies", nil, token)
	case "proof":
		return call("POST", "/api/v1/local-services/proof", p.Request.Proof, token)
	case "execute":
		return call("POST", "/api/v1/local-services/transactions", p.Request.Transaction, token)
	}
	return resultError(probeProtocol)
}

func probeSSH(ctx context.Context, p probeLaunch, dialer *net.Dialer, network, target string) ProbeResult {
	key, _, _, rest, e := ssh.ParseAuthorizedKey(p.HostKey)
	if e != nil || len(bytes.TrimSpace(rest)) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return resultError(probeHostKey)
	}
	raw, e := dialer.DialContext(ctx, network, target)
	if e != nil {
		return resultError(dialError(e))
	}
	defer raw.Close()
	if raw.SetDeadline(time.Now().Add(10*time.Second)) != nil {
		return resultError(probeProtocol)
	}
	if p.Request.Session == "" {
		return resultError(probeAuth)
	}
	password := "session:" + p.Request.Session
	alg := ssh.SupportedAlgorithms()
	config := &ssh.ClientConfig{Config: ssh.Config{KeyExchanges: alg.KeyExchanges, Ciphers: alg.Ciphers, MACs: alg.MACs}, User: p.Request.Username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
		if !bytes.Equal(actual.Marshal(), key.Marshal()) {
			return probeHostKey
		}
		return nil
	}, Timeout: 5 * time.Second}
	conn, chans, requests, e := ssh.NewClientConn(raw, target, config)
	if e != nil {
		var pe probeError
		if errors.As(e, &pe) {
			return resultError(pe)
		}
		return resultError(probeAuth)
	}
	client := ssh.NewClient(conn, chans, requests)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		return resultError(probeProtocol)
	}
	defer session.Close()
	var input any = struct{}{}
	if p.Request.Proof != nil {
		input = p.Request.Proof
	}
	if p.Request.Transaction != nil {
		input = p.Request.Transaction
	}
	// Status has no request body and the server can finish without reading stdin.
	// Sending an unused body races that close and can turn exit status zero into
	// a client-side copy error. Typed commands that consume JSON retain their body.
	if p.Request.Operation != "status" {
		session.Stdin = bytes.NewReader(encode(input))
	}
	var output boundedOutput
	session.Stdout = &output
	session.Stderr = io.Discard
	e = session.Run("andeiva local-services " + p.Request.Operation)
	if output.overflow {
		return resultError(probeProtocol)
	}
	var reply struct {
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if firewallipc.Decode(output.Bytes(), &reply) != nil {
		return resultError(probeProtocol)
	}
	if e != nil {
		if reply.Error == "" {
			return resultError(probeProtocol)
		}
		return ProbeResult{Status: 403, Error: reply.Error}
	}
	return ProbeResult{Status: 200, Data: reply.Data}
}
