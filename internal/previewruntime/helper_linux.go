//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type helperOutput struct{ bytes.Buffer }

func (b *helperOutput) Write(p []byte) (int, error) {
	if len(p) > 512<<10-b.Len() {
		return 0, errHelper
	}
	return b.Buffer.Write(p)
}

type helperTransport struct{ namespace uint64 }

func (t helperTransport) execute(parent context.Context, input []byte, operation string) ([]byte, error) {
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil || current != t.namespace || t.namespace == 0 {
		return nil, errHelper
	}
	if len(input) > 512<<10 {
		return nil, errHelper
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch operation {
	case "check":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "--check", "-j", "-f", "-")
	case "apply":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
	case "observe":
		if len(input) != 0 {
			return nil, errHelper
		}
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "andeiva_admin")
	default:
		return nil, errHelper
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	var output, diagnostic helperOutput
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	cmd.WaitDelay = 200 * time.Millisecond
	if cmd.Run() != nil {
		return nil, errHelper
	}
	return output.Bytes(), nil
}
func (t helperTransport) Check(ctx context.Context, input []byte) error {
	_, err := t.execute(ctx, input, "check")
	return err
}
func (t helperTransport) Apply(ctx context.Context, input []byte) error {
	_, err := t.execute(ctx, input, "apply")
	return err
}
func (t helperTransport) Observe(ctx context.Context) ([]byte, error) {
	return t.execute(ctx, nil, "observe")
}

func privilegeFields(status string, network bool) error {
	fields := map[string]string{}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "Cap") || key == "NoNewPrivs" {
			if _, exists := fields[key]; exists {
				return errHelper
			}
			fields[key] = strings.TrimSpace(value)
		}
	}
	var expected uint64
	if network {
		expected = 1 << 12
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, err := strconv.ParseUint(fields[key], 16, 64)
		if err != nil || value != expected {
			return errHelper
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errHelper
	}
	return nil
}

// Widen both operands before comparison: negative IDs and values outside the
// kernel's uint32 identity range must never wrap into an authorized identity.
func matchesIdentity(actual int, expected uint32) bool {
	return actual >= 0 && int64(actual) == int64(expected)
}

func checkPrivileges(ids Identities, helper bool) error {
	uid, gid := ids.APIUID, ids.APIGID
	if helper {
		uid, gid = ids.HelperUID, ids.IPCGID
	}
	if !matchesIdentity(os.Getuid(), uid) || !matchesIdentity(os.Geteuid(), uid) || !matchesIdentity(os.Getgid(), gid) || !matchesIdentity(os.Getegid(), gid) {
		return ErrIdentity
	}
	groups, e := os.Getgroups()
	if e != nil {
		return ErrIdentity
	}
	hasIPC := gid == ids.IPCGID
	for _, g := range groups {
		if matchesIdentity(g, ids.IPCGID) {
			hasIPC = true
		} else if helper || !matchesIdentity(g, ids.APIGID) {
			return ErrIdentity
		}
	}
	if !hasIPC {
		return ErrIdentity
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil || len(status) > 65536 {
		return ErrIdentity
	}
	return privilegeFields(string(status), helper)
}
func Helper(ctx context.Context, c Config) error {
	ids, e := LoadIdentities(c)
	if e != nil {
		return e
	}
	if checkPrivileges(ids, true) != nil {
		return ErrIdentity
	}
	m, e := ReadMetadata()
	if e != nil {
		return e
	}
	current, e := namespaceID("/proc/self/ns/net")
	if e != nil || current != m.GatewayNamespace || current == m.HostNamespace {
		return ErrIdentity
	}
	transport := helperTransport{namespace: current}
	// The namespace owner seals the table before starting us. Never create a
	// duplicate table or accept an unknown initial policy.
	data, e := transport.Observe(ctx)
	if e != nil {
		return e
	}
	observation, e := firewallnft.InspectObservation(data)
	if e != nil {
		return ErrUnavailable
	}
	initial, e := firewallnft.Compile(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if e != nil || observation.Revision.Hash != initial.Revision.Hash {
		return ErrUnavailable
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrUnavailable
	}
	run := hex.EncodeToString(nonce[:])
	engine := NewCounterEngine(run, firewallnft.New(transport), func(ctx context.Context) (string, []firewallipc.Counter, error) {
		data, e := transport.Observe(ctx)
		if e != nil {
			return "", nil, e
		}
		o, e := firewallnft.InspectObservation(data)
		if e != nil {
			return "", nil, ErrUnavailable
		}
		counters := make([]firewallipc.Counter, 0, len(o.Rules))
		for _, r := range o.Rules {
			counters = append(counters, firewallipc.Counter{ID: r.ID, Packets: r.Packets, Bytes: r.Bytes})
		}
		return o.Revision.Hash, counters, nil
	})
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	s := NewSession(run, current, engine, guardian, engine.Observe)
	l, e := listenPrivate(HelperSocket, ids.HelperUID, ids.IPCGID)
	if e != nil {
		return e
	}
	st, e := os.Lstat(HelperSocket)
	if e != nil {
		_ = l.Close()
		return ErrStorage
	}
	defer removeSocket(HelperSocket, st)
	defer l.Close()
	if notifyReady() != nil {
		return ErrUnavailable
	}
	return serveController(ctx, l, m, ids, s)
}
