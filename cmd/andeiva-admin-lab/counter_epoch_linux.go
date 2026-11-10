package main

import (
	"context"
	"strconv"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// counterEngine serializes readback with every engine application, including
// guardian compensation and no-op reapplication. An attempted apply invalidates
// continuity even if it fails or the effective policy hash does not change.
type counterEngine struct {
	mu         sync.Mutex
	engine     helperEngine
	read       func(context.Context) (string, []firewallipc.Counter, error)
	run        string
	generation uint64
	exhausted  bool
}

func (e *counterEngine) Apply(ctx context.Context, r configpoc.Revision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exhausted || e.generation == ^uint64(0) {
		e.exhausted = true
		return errHelper
	}
	e.generation++
	return e.engine.Apply(ctx, r)
}
func (e *counterEngine) Current() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exhausted {
		return ""
	}
	return e.engine.Current()
}
func (e *counterEngine) Observe(ctx context.Context) (string, []firewallipc.Counter, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exhausted || ctx.Err() != nil {
		return "", nil, "", errHelper
	}
	hash, counters, err := e.read(ctx)
	if err != nil || hash == "" || e.engine.Current() != hash || ctx.Err() != nil {
		return "", nil, "", errHelper
	}
	return hash, counters, e.run + "." + strconv.FormatUint(e.generation, 10), nil
}
