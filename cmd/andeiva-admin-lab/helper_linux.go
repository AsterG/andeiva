package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

var errHelper = errors.New("ANDEIVA_ADMIN_HELPER_UNAVAILABLE")
var helperLease = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

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

func namespaceID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, errHelper
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, errHelper
	}
	return stat.Ino, nil
}
func bindParent(value string) error {
	parent, err := strconv.Atoi(value)
	if err != nil || parent <= 1 || strconv.Itoa(parent) != value || os.Getppid() != parent {
		return errHelper
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0, 0)
	if errno != 0 || os.Getppid() != parent {
		return errHelper
	}
	return nil
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
func checkPrivileges(network bool) error {
	if os.Getuid() != 1001 || os.Geteuid() != 1001 || os.Getgid() != 1001 || os.Getegid() != 1001 {
		return errHelper
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errHelper
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) > 65536 {
		return errHelper
	}
	return privilegeFields(string(status), network)
}

type helperEngine interface {
	Apply(context.Context, configpoc.Revision) error
	Current() string
}
type helperObserver func(context.Context) (string, []firewallipc.Counter, error)
type helperSession struct {
	run                    string
	namespace, last, epoch uint64
	recovering             bool
	applied                string
	engine                 helperEngine
	guardian               *nftguardian.Guardian
	observe                helperObserver
}

func validHex(value string, length int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == length && hex.EncodeToString(decoded) == value
}
func zeroRevision(r configpoc.Revision) bool {
	return r.Hash == "" && r.Config.SchemaVersion == 0 && r.Config.DefaultAction == "" && len(r.Config.Rules) == 0
}
func validRevision(r configpoc.Revision) bool {
	a, err := firewallnft.Compile(r.Config)
	return err == nil && a.Revision.Hash == r.Hash
}
func validHelperMessage(m firewallipc.Message) bool {
	switch m.Verb {
	case "bootstrap", "apply":
		return validRevision(m.Revision) && zeroRevision(m.Previous) && m.Hash == "" && m.Lease == "" && m.TTL == 0
	case "arm":
		return validRevision(m.Revision) && validRevision(m.Previous) && helperLease.MatchString(m.Lease) && m.Hash == "" && m.TTL >= 500*time.Millisecond && m.TTL <= 120*time.Second
	case "confirm":
		return zeroRevision(m.Revision) && zeroRevision(m.Previous) && helperLease.MatchString(m.Lease) && validHex(m.Hash, 32) && m.TTL == 0
	case "state", "observe", "recovered":
		return zeroRevision(m.Revision) && zeroRevision(m.Previous) && m.Hash == "" && m.Lease == "" && m.TTL == 0
	default:
		return false
	}
}

// handle binds a new API epoch to boot/resume recovery before accepting leases.
// Protocol violations close the channel; valid rejected operations get a bounded reply.
func (s *helperSession) handle(ctx context.Context, m firewallipc.Message) (firewallipc.Reply, error) {
	epoch := m.Sequence >> 32
	ordinal := m.Sequence & 0xffffffff
	if m.Run != s.run || epoch == 0 || ordinal == 0 || m.Sequence <= s.last || !validHelperMessage(m) {
		return firewallipc.Reply{}, errHelper
	}
	if epoch != s.epoch {
		if epoch <= s.epoch || ordinal != 1 {
			return firewallipc.Reply{}, errHelper
		}
		s.epoch = epoch
		s.recovering = true
		s.applied = ""
	} else if m.Sequence != s.last+1 {
		return firewallipc.Reply{}, errHelper
	}
	s.last = m.Sequence
	reply := firewallipc.Reply{Run: s.run, Sequence: m.Sequence, Namespace: s.namespace}
	if m.Verb == "bootstrap" || m.Verb == "apply" || m.Verb == "arm" {
		artifact, _ := firewallnft.Compile(m.Revision.Config)
		reply.Artifact = artifact.Digest
	}
	var err error
	switch m.Verb {
	case "bootstrap":
		if !s.recovering {
			err = errHelper
		} else {
			err = s.guardian.Bootstrap(ctx, m.Revision)
		}
		if err == nil {
			s.applied = m.Revision.Hash
		}
	case "apply":
		state := s.guardian.Status()
		// A no-op pending transition still needs its old lease cleared on API
		// restart. Both trusted revisions and effective readback must coincide.
		if s.recovering && (state.Phase == "armed" || state.Phase == "pending") && state.Previous == state.Target && state.Previous == m.Revision.Hash && s.engine.Current() == m.Revision.Hash {
			err = s.guardian.RecoverPrevious()
		}
		if err == nil {
			err = s.guardian.Apply(ctx, m.Revision)
		}
		if err == nil && s.recovering {
			s.applied = m.Revision.Hash
		}
	case "arm":
		if s.recovering {
			err = errHelper
		} else {
			state := s.guardian.Status()
			if state.Phase == "expired" {
				if m.Previous.Hash != state.Previous || s.engine.Current() != state.Previous {
					err = errHelper
				} else {
					err = s.guardian.RecoverPrevious()
				}
			}
			if err == nil {
				err = s.guardian.Arm(m.Lease, m.Previous, m.Revision, m.TTL)
			}
		}
	case "confirm":
		if s.recovering {
			err = errHelper
		} else {
			err = s.guardian.Confirm(m.Lease, m.Hash)
		}
	case "recovered":
		state := s.guardian.Status()
		if !s.recovering || s.applied == "" || s.engine.Current() != s.applied || (state.Phase != "idle" && state.Phase != "expired") {
			err = errHelper
		} else if state.Phase == "expired" {
			err = s.guardian.RecoverPrevious()
		}
		if err == nil {
			s.recovering = false
		}
	case "observe":
		reply.Hash, reply.Counters, err = s.observe(ctx)
		if err == nil && (reply.Hash == "" || s.engine.Current() != reply.Hash) {
			err = errHelper
		}
	case "state":
	}
	state := s.guardian.Status()
	reply.State = firewalladmin.LeaseState{Phase: state.Phase, ID: state.ID, Previous: state.Previous, Target: state.Target, Deadline: state.Deadline}
	if err != nil {
		reply.Error = errHelper.Error()
		reply.Hash = ""
		reply.Counters = nil
	}
	return reply, nil
}
func (s *helperSession) serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), firewallipc.MaxFrame)
	for scanner.Scan() {
		var message firewallipc.Message
		if firewallipc.Decode(scanner.Bytes(), &message) != nil {
			return errHelper
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		reply, err := s.handle(ctx, message)
		cancel()
		if err != nil {
			return err
		}
		if json.NewEncoder(output).Encode(reply) != nil {
			return errHelper
		}
	}
	if scanner.Err() != nil {
		return errHelper
	}
	return io.EOF
}
func helperProcess(run, hostValue, parent string) error {
	host, err := strconv.ParseUint(hostValue, 10, 64)
	if err != nil || host == 0 || strconv.FormatUint(host, 10) != hostValue || !validHex(run, 16) {
		return errHelper
	}
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil || current == host {
		return errHelper
	}
	pinned, err := namespaceID("/proc/self/fd/3")
	if err != nil || pinned != current {
		return errHelper
	}
	if err = bindParent(parent); err != nil {
		return err
	}
	if err = checkPrivileges(true); err != nil {
		return err
	}
	for _, file := range []*os.File{os.Stdin, os.Stdout} {
		info, e := file.Stat()
		if e != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return errHelper
		}
	}
	transport := helperTransport{namespace: current}
	initial, err := firewallnft.Compile(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		return errHelper
	}
	if transport.Check(context.Background(), initial.Create) != nil || transport.Apply(context.Background(), initial.Create) != nil {
		return errHelper
	}
	engine := firewallnft.New(transport)
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	session := helperSession{run: run, namespace: current, engine: engine, guardian: guardian, observe: func(ctx context.Context) (string, []firewallipc.Counter, error) {
		data, err := transport.Observe(ctx)
		if err != nil {
			return "", nil, errHelper
		}
		observation, err := firewallnft.InspectObservation(data)
		if err != nil {
			return "", nil, errHelper
		}
		counters := make([]firewallipc.Counter, 0, len(observation.Rules))
		for _, counter := range observation.Rules {
			counters = append(counters, firewallipc.Counter{ID: counter.ID, Packets: counter.Packets, Bytes: counter.Bytes})
		}
		return observation.Revision.Hash, counters, nil
	}}
	return session.serve(os.Stdin, os.Stdout)
}
