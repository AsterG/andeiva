package firewallipc

import (
	"bytes"
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type closedStreamV2 struct {
	bytes.Buffer
	closed int
}

func (c *closedStreamV2) Close() error { c.closed++; return nil }

func TestClientV2IncompleteValuesFailClosed(t *testing.T) {
	for _, c := range []*ClientV2{nil, {}} {
		if c.Close() != nil || c.Close() != nil || c.Name() != "" || c.Validate(configpoc.Config{}) == nil {
			t.Fatal("incomplete client")
		}
		if _, e := c.State(context.Background()); e == nil {
			t.Fatal("incomplete state")
		}
	}
}
func TestConnectV2OwnsAllFailurePaths(t *testing.T) {
	compile := func(configpoc.Config) (string, error) { return "", nil }
	for _, kind := range []string{"nil-parent", "cancelled", "nil-compile", "invalid-hello", "lost-hello"} {
		t.Run(kind, func(t *testing.T) {
			conn := &closedStreamV2{}
			ctx := context.Background()
			run := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			compiler := Compiler(compile)
			switch kind {
			case "nil-parent":
				ctx = nil
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "nil-compile":
				compiler = nil
			case "invalid-hello":
				run = "invalid"
			}
			if _, e := ConnectV2(ctx, conn, run, 42, "firewall", compiler); e == nil || conn.closed != 1 {
				t.Fatal("failure leaked owned stream", conn.closed, e)
			}
		})
	}
}
