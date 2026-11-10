package main

import (
	"bufio"
	"bytes"
	"context"

	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"

	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/previewruntime"
)

var errHelper = errors.New("ANDEIVA_ADMIN_HELPER_UNAVAILABLE")

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
type helperObserver func(context.Context) (string, []firewallipc.Counter, string, error)
type helperSession struct {
	run                    string
	namespace, last, epoch uint64
	engine                 helperEngine
	guardian               *nftguardian.Guardian
	observe                helperObserver
	delegate               *previewruntime.Session
}

func (s *helperSession) handle(ctx context.Context, m firewallipc.Message) (firewallipc.Reply, error) {
	if s.delegate == nil {
		s.delegate = previewruntime.NewSession(s.run, s.namespace, s.engine, s.guardian, func(ctx context.Context) (string, []firewallipc.Counter, string, error) { return s.observe(ctx) })
	}
	reply, err := s.delegate.Handle(ctx, m)
	s.last, s.epoch = s.delegate.Position()
	return reply, err
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
	if err != nil || host == 0 || strconv.FormatUint(host, 10) != hostValue || !previewruntime.ValidRun(run) {
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
	engine := &counterEngine{run: run, engine: firewallnft.New(transport), read: func(ctx context.Context) (string, []firewallipc.Counter, error) {
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
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	session := helperSession{run: run, namespace: current, engine: engine, guardian: guardian, observe: engine.Observe}
	return session.serve(os.Stdin, os.Stdout)
}
