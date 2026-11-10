package localssh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"golang.org/x/crypto/ssh"
)

const MaxInputBytes = 64 * 1024
const MaxOutputBytes = 1024 * 1024

type response struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}
type historyRequest struct {
	Before uint64 `json:"before"`
	Limit  int    `json:"limit"`
}

func (s *Server) command(ctx context.Context, ch ssh.Channel, requests <-chan *ssh.Request, caller localadmin.Context, token string) {
	var request *ssh.Request
	select {
	case <-ctx.Done():
		return
	case r, ok := <-requests:
		if !ok {
			return
		}
		request = r
	}
	var payload struct{ Command string }
	if request.Type != "exec" || len(request.Payload) > 160 || ssh.Unmarshal(request.Payload, &payload) != nil {
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
		s.event(caller.Principal.ID, "ssh-channel", "denied")
		return
	}
	verb, ok := strings.CutPrefix(payload.Command, "andeiva local-services ")
	switch verb {
	case "status", "effective", "history", "audit", "proof", "execute":
	default:
		ok = false
	}
	if !ok {
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
		s.event(caller.Principal.ID, "ssh-command", "denied")
		return
	}
	if request.WantReply {
		if err := request.Reply(true, nil); err != nil {
			return
		}
	}
	// Reject additional channel requests while input or backend work is pending.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range requests {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			s.event(caller.Principal.ID, "ssh-channel", "denied")
			_ = ch.Close()
			return
		}
	}()
	defer func() { _ = ch.Close(); <-done }()
	data, err := s.dispatch(ctx, ch, caller, token, verb)
	result := "ok"
	if err != nil {
		result = "denied"
	}
	if !s.event(caller.Principal.ID, "ssh-command", result) {
		return
	}
	out := response{Data: data}
	code := uint32(0)
	if err != nil {
		out = response{Error: publicError(err)}
		code = 2
	}
	b, encodeErr := json.Marshal(out)
	if encodeErr != nil || len(b) > MaxOutputBytes {
		b = []byte(`{"error":"ANDEIVA_LOCAL_SSH_UNAVAILABLE"}`)
		code = 2
	}
	if _, err := ch.Write(append(b, '\n')); err != nil {
		return
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
}

func decode(r io.Reader, out any) error {
	b, err := io.ReadAll(io.LimitReader(r, MaxInputBytes+1))
	if err != nil || len(b) > MaxInputBytes {
		return configpoc.ErrInvalid
	}
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '{' || b[len(b)-1] != '}' {
		return configpoc.ErrInvalid
	}
	if firewallipc.Decode(b, out) != nil {
		return configpoc.ErrInvalid
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, input io.Reader, caller localadmin.Context, token, verb string) (any, error) {
	// Recheck the live auth session after channel opening; transport credentials
	// never become an enduring authorization grant after session revocation.
	if err := s.authorize(ctx, caller, token, verb); err != nil {
		return nil, err
	}
	switch verb {
	case "status":
		return s.options.Backend.Status(ctx, caller)
	case "effective":
		var f localadmin.Filter
		if decode(input, &f) != nil {
			return nil, configpoc.ErrInvalid
		}
		if err := s.authorize(ctx, caller, token, verb); err != nil {
			return nil, err
		}
		return s.options.Backend.Effective(ctx, caller, f)
	case "history":
		var r historyRequest
		if decode(input, &r) != nil || r.Limit < 1 || r.Limit > 100 {
			return nil, configpoc.ErrInvalid
		}
		if err := s.authorize(ctx, caller, token, verb); err != nil {
			return nil, err
		}
		return s.options.Backend.History(caller, r.Before, r.Limit)
	case "audit":
		return s.options.Backend.Audit(caller)
	case "proof":
		var r localadmin.ProofRequest
		if decode(input, &r) != nil {
			return nil, configpoc.ErrInvalid
		}
		if err := s.authorize(ctx, caller, token, verb); err != nil {
			return nil, err
		}
		return s.options.Backend.IssueProof(caller, r)
	case "execute":
		var r localadmin.Request
		if decode(input, &r) != nil {
			return nil, configpoc.ErrInvalid
		}
		if err := s.authorize(ctx, caller, token, verb); err != nil {
			return nil, err
		}
		return s.options.Backend.Execute(ctx, caller, r)
	default:
		return nil, configpoc.ErrInvalid
	}
}

func (s *Server) authorize(ctx context.Context, caller localadmin.Context, token, verb string) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	identity, err := s.options.Auth.Authenticate(token)
	if err != nil || identity.Username != caller.Principal.ID || identity.Role != string(caller.Principal.Role) {
		return adminauth.ErrDenied
	}
	if caller.Principal.Role != configpoc.RoleAdmin && verb != "status" && verb != "effective" {
		return configpoc.ErrDenied
	}
	return nil
}

func publicError(err error) string {
	for _, known := range []error{configpoc.ErrDenied, configpoc.ErrInvalid, configpoc.ErrConflict, configpoc.ErrPending, configpoc.ErrExpired, configpoc.ErrReplay, configpoc.ErrStorage, configpoc.ErrRecovery, adminauth.ErrDenied, adminauth.ErrLimited, adminauth.ErrUnavailable} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return ErrUnavailable.Error()
}
