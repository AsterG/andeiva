package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/nftpoc"
)

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("ANDEIVA_NFT_OUTPUT_LIMIT")
	}
	return b.Buffer.Write(p)
}

type nftTransport struct{}

func (nftTransport) execute(ctx context.Context, input []byte, operation string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch operation {
	case "check":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "--check", "-j", "-f", "-")
	case "apply":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
	case "observe":
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "andeiva_poc")
	default:
		return nil, errProtocol
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	var output, diagnostic boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	cmd.WaitDelay = 200 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ANDEIVA_NFT_EXEC: %w: %s", err, diagnostic.String())
	}
	return output.Bytes(), nil
}
func (t nftTransport) Check(ctx context.Context, b []byte) error {
	_, err := t.execute(ctx, b, "check")
	return err
}
func (t nftTransport) Apply(ctx context.Context, b []byte) error {
	_, err := t.execute(ctx, b, "apply")
	return err
}
func (t nftTransport) Observe(ctx context.Context) ([]byte, error) {
	return t.execute(ctx, nil, "observe")
}

func namespaceID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errProtocol
	}
	return s.Ino, nil
}

func guardian(runID, hostID, parentID string) error {
	host, err := strconv.ParseUint(hostID, 10, 64)
	if err != nil {
		return errProtocol
	}
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil || current == host {
		return errProtocol
	}
	pinned, err := namespaceID("/proc/self/fd/3")
	if err != nil || pinned != current {
		return errProtocol
	}
	parent, err := strconv.Atoi(parentID)
	if err != nil || os.Getppid() != parent {
		return errProtocol
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0, 0)
	if errno != 0 || os.Getppid() != parent {
		return errProtocol
	}
	if os.Geteuid() == 0 {
		return errors.New("ANDEIVA_NFT_HELPER_REQUIRES_UNPRIVILEGED_UID")
	}
	t := nftTransport{}
	a, err := nftpoc.Compile(nftpoc.DefaultConfig())
	if err != nil {
		return err
	}
	if err = t.Check(context.Background(), a.Create); err != nil {
		return err
	}
	if err = t.Apply(context.Background(), a.Create); err != nil {
		return err
	}
	engine := nftpoc.New(t)
	g := nftguardian.New(engine)
	defer g.Close()
	s := scanner(os.Stdin)
	var last uint64
	for s.Scan() {
		var m message
		if err = decode(s.Bytes(), &m); err != nil {
			return err
		}
		if m.Run != runID || m.Sequence <= last {
			return errProtocol
		}
		last = m.Sequence
		r := reply{Run: runID, Sequence: m.Sequence, Namespace: current}
		if artifact, e := nftpoc.Compile(m.Revision.Config); e == nil {
			r.Artifact = artifact.Digest
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		switch m.Verb {
		case "validate":
			err = engine.Validate(m.Revision.Config)
		case "apply":
			err = g.Apply(ctx, m.Revision)
		case "current":
			r.Hash = engine.Current()
			if r.Hash == "" {
				err = errors.New("ANDEIVA_NFT_OBSERVATION_FAILED")
			} else {
				err = nil
			}
		case "arm":
			err = g.Arm(m.Lease, m.Previous, m.Revision, m.TTL)
		case "confirm":
			err = g.Confirm(m.Lease, m.Revision.Hash)
		case "recover":
			err = g.RecoverPrevious()
		case "authority":
			err = nil
		default:
			err = errProtocol
		}
		cancel()
		r.State = g.Status()
		if err != nil {
			r.Error = err.Error()
			if observation, readErr := t.Observe(context.Background()); readErr == nil {
				_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "failed_operation_readback", "observation": json.RawMessage(observation)})
			}
		}
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "guardian_operation", "sequence": m.Sequence, "verb": m.Verb, "revision": m.Revision.Hash, "artifact": r.Artifact, "phase": r.State.Phase, "error": r.Error, "namespace": current})
		if err = json.NewEncoder(os.Stdout).Encode(r); err != nil {
			return err
		}
	}
	if err = s.Err(); err != nil {
		return err
	}
	return io.EOF
}
