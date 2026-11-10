package main

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestProtocolRejectsUnknownAndUnboundedInput(t *testing.T) {
	for _, data := range []string{`{"verb":"apply","command":"flush ruleset"}`, `{"verb":"apply","verb":"current"}`, `{} {}`, `nullx`, string(make([]byte, maxMessage+1))} {
		var m message
		if decode([]byte(data), &m) == nil {
			t.Fatalf("accepted invalid message length %d", len(data))
		}
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
