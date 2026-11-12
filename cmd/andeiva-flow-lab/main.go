// andeiva-flow-lab is a one-shot, read-only current-namespace laboratory observer.
// Its output is sensitive platform evidence; no public API is exposed here.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AsterG/andeiva/internal/routedflow"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "ANDEIVA_ROUTED_FLOW_INVALID_ARGUMENTS")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	snapshot, e := routedflow.Collect(ctx)
	stop() // Restore default signal handling before writing to a caller-owned pipe.
	if e != nil {
		code := e.Error()
		if errors.Is(e, context.DeadlineExceeded) {
			code = "ANDEIVA_ROUTED_FLOW_TIMEOUT"
		}
		if errors.Is(e, context.Canceled) {
			code = "ANDEIVA_ROUTED_FLOW_CANCELLED"
		}
		fmt.Fprintln(os.Stderr, code)
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(snapshot); e != nil {
		fmt.Fprintln(os.Stderr, "ANDEIVA_ROUTED_FLOW_OUTPUT")
		os.Exit(1)
	}
}
