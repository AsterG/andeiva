package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func pair(t *testing.T, handle func(Message) Reply) *Client {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	c, err := New(a, a, strings.Repeat("a", 32), uint64(1)<<32, 42, func(configpoc.Config) (string, error) { return "digest", nil })
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		scan := bufio.NewScanner(b)
		for scan.Scan() {
			var m Message
			if Decode(scan.Bytes(), &m) != nil {
				return
			}
			r := handle(m)
			if json.NewEncoder(b).Encode(r) != nil {
				return
			}
		}
	}()
	return c
}
func bound(m Message) Reply {
	return Reply{Run: m.Run, Sequence: m.Sequence, Namespace: 42, Artifact: "digest", Hash: "verified"}
}

func TestChannelBindsEveryReplyAndPoisonsInvalidChannel(t *testing.T) {
	for _, field := range []string{"run", "sequence", "namespace", "artifact"} {
		t.Run(field, func(t *testing.T) {
			c := pair(t, func(m Message) Reply {
				r := bound(m)
				switch field {
				case "run":
					r.Run = "other"
				case "sequence":
					r.Sequence--
				case "namespace":
					r.Namespace++
				case "artifact":
					r.Artifact = "other"
				}
				return r
			})
			revision, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny"})
			if _, err := c.Call(context.Background(), Message{Verb: "apply", Revision: revision}); !errors.Is(err, ErrChannel) {
				t.Fatal(err)
			}
			if _, err := c.Call(context.Background(), Message{Verb: "observe"}); !errors.Is(err, ErrChannel) {
				t.Fatal("channel reused", err)
			}
		})
	}
}
func TestChannelSerializesConcurrentRequests(t *testing.T) {
	var last uint64 = uint64(1) << 32
	c := pair(t, func(m Message) Reply {
		if m.Sequence != last+1 {
			t.Error("nonmonotonic request")
		}
		last = m.Sequence
		return bound(m)
	})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := c.Observe(context.Background())
			if e != nil || r.Hash != "verified" {
				t.Error(r, e)
			}
		}()
	}
	wg.Wait()
}
func TestCanceledChannelCannotBeReused(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c, _ := New(a, a, strings.Repeat("a", 32), 0, 42, func(configpoc.Config) (string, error) { return "", nil })
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Observe(ctx); err == nil {
		t.Fatal("blocked pipe accepted")
	}
	if _, err := c.Observe(context.Background()); err == nil {
		t.Fatal("timed out channel reused")
	}
}
func TestHelperErrorIsGenericButKeepsBoundChannel(t *testing.T) {
	first := true
	c := pair(t, func(m Message) Reply {
		r := bound(m)
		if first {
			r.Error = "private detail"
			first = false
		}
		return r
	})
	if _, e := c.Observe(context.Background()); e != ErrChannel {
		t.Fatal(e)
	}
	if _, e := c.Observe(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestDecodeRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	for _, s := range []string{`{"run":"a","run":"b"}`, `{"run":"a","RUN":"b"}`, `{"unknown":1}`, `{} {}`, `{"run":`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), strings.Repeat(" ", MaxFrame+1)} {
		var m Message
		if Decode([]byte(s), &m) == nil {
			t.Fatal("accepted", s[:min(len(s), 80)])
		}
	}
	var m Message
	if Decode([]byte(`{"run":"a","sequence":1,"verb":"state","revision":{"hash":"","config":{"schema_version":2,"rules":[],"default_action":"deny"}},"previous":{"hash":"","config":{"schema_version":2,"rules":[],"default_action":"deny"}}}`), &m) != nil {
		t.Fatal("valid message rejected")
	}
}
