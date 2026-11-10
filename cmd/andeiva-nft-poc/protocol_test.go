package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/nftpoc"
)

func TestProtocolRejectsUnknownAndUnboundedInput(t *testing.T) {
	for _, data := range []string{`{"verb":"apply","command":"flush ruleset"}`, `{"verb":"apply","verb":"current"}`, `{} {}`, `null`, `[]`, `nullx`, string(make([]byte, maxMessage+1))} {
		var m message
		if decode([]byte(data), &m) == nil {
			t.Fatalf("accepted invalid message length %d", len(data))
		}
	}
}

type discardCloser struct{ io.Writer }

func (discardCloser) Close() error { return nil }

func TestInvalidReplyPoisonsChannel(t *testing.T) {
	a, err := nftpoc.Compile(nftpoc.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"malformed", "run", "sequence", "namespace", "artifact", "missing-artifact", "eof"} {
		t.Run(kind, func(t *testing.T) {
			r := reply{Run: "test", Sequence: 1, Namespace: 42, Artifact: a.Digest}
			switch kind {
			case "run":
				r.Run = "other"
			case "sequence":
				r.Sequence++
			case "namespace":
				r.Namespace++
			case "artifact":
				r.Artifact = strings.Repeat("0", 64)
			case "missing-artifact":
				r.Artifact = ""
			}
			data, _ := json.Marshal(r)
			if kind == "malformed" {
				data = []byte(`{"run":`)
			}
			if kind == "eof" {
				data = nil
			}
			input := io.NopCloser(strings.NewReader(string(data)))
			c := &channel{run: "test", expectedNamespace: 42, out: discardCloser{io.Discard}, input: input, in: scanner(input)}
			if _, err := c.call(message{Verb: "apply", Revision: a.Revision}); err == nil {
				t.Fatal("invalid reply accepted")
			}
			if !c.dead {
				t.Fatal("invalid reply did not poison channel")
			}
			if _, err := c.call(message{Verb: "current"}); err == nil {
				t.Fatal("poisoned channel reused")
			}
		})
	}
}

func TestBoundOperationErrorDoesNotPoisonChannel(t *testing.T) {
	input := io.NopCloser(strings.NewReader("{\"run\":\"test\",\"sequence\":1,\"namespace\":42,\"error\":\"denied\"}\n{\"run\":\"test\",\"sequence\":2,\"namespace\":42,\"hash\":\"current\"}\n"))
	c := &channel{run: "test", expectedNamespace: 42, out: discardCloser{io.Discard}, input: input, in: scanner(input)}
	if _, err := c.call(message{Verb: "authority"}); err == nil || c.dead {
		t.Fatal("bound operation rejection mishandled")
	}
	if r, err := c.call(message{Verb: "current"}); err != nil || r.Hash != "current" {
		t.Fatal("valid channel lost")
	}
}

func TestBlockedChannelExpiresAndCannotBeReused(t *testing.T) {
	r, w := io.Pipe()
	responseR, responseW := io.Pipe()
	defer r.Close()
	defer responseW.Close()
	c := &channel{run: "test", out: w, input: responseR, in: scanner(responseR)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.callContext(ctx, message{Verb: "current"}); err == nil {
		t.Fatal("blocked channel succeeded")
	}
	if _, err := c.call(message{Verb: "current"}); err == nil {
		t.Fatal("expired channel reused")
	}
}
