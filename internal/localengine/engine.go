// Package localengine coordinates verified Local-In rules and managed listeners.
package localengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

var ErrState = errors.New("ANDEIVA_LOCAL_STATE_UNVERIFIED")

// Transport is confined to the owned namespace and the fixed andeiva_local table.
// An absent table must be established by a successful kernel query, not inferred
// from a command failure. Implementations bound every read and operation.
type Transport interface {
	Check(context.Context, []byte) error
	Apply(context.Context, []byte) error
	Observe(context.Context) ([]byte, bool, error)
}

// Listeners runs without network-administration privileges. Apply must retire
// old connections as well as sockets. Observe independently verifies actual
// sockets and ownership; returning a cached declaration is not sufficient.
type Listeners interface {
	Apply(context.Context, configpoc.Revision) error
	Observe(context.Context) ([]localpolicy.Listener, error)
}

type Observation struct {
	Hash  string                  `json:"hash"`
	Local localpolicy.Observation `json:"local"`
}

type Engine struct {
	mu        sync.Mutex
	transport Transport
	listeners Listeners
	inventory []localpolicy.Interface
	neighbors []localnft.NeighborLink
	current   *configpoc.Revision
	artifact  localnft.Artifact
	owned     bool
}

func New(t Transport, listeners Listeners, inventory []localpolicy.Interface, neighbors []localnft.NeighborLink) (*Engine, error) {
	if t == nil || listeners == nil || len(inventory) == 0 {
		return nil, ErrState
	}
	base, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: inventory, Services: []localpolicy.Service{}})
	if err != nil {
		return nil, err
	}
	a, err := localnft.CompileWithNeighbors(base.Config, neighbors)
	if err != nil {
		return nil, err
	}
	return &Engine{transport: t, listeners: listeners, inventory: base.Config.Interfaces, neighbors: a.Neighbors}, nil
}

func (*Engine) Name() string { return "local-services" }

func (e *Engine) compile(c configpoc.Config) (configpoc.Revision, localnft.Artifact, error) {
	r, err := configpoc.Canonical(c)
	if err != nil || r.Config.DefaultAction != "deny" || len(r.Config.Rules) != 0 {
		return configpoc.Revision{}, localnft.Artifact{}, ErrState
	}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: e.inventory, Services: []localpolicy.Service{}}
	if r.Config.LocalServices != nil {
		local = *r.Config.LocalServices
	}
	want, _ := json.Marshal(e.inventory)
	got, _ := json.Marshal(local.Interfaces)
	if !bytes.Equal(want, got) || localnft.ValidateManaged(local) != nil {
		return configpoc.Revision{}, localnft.Artifact{}, ErrState
	}
	a, err := localnft.CompileWithNeighbors(local, e.neighbors)
	return r, a, err
}

func (e *Engine) Validate(c configpoc.Config) error {
	_, _, err := e.compile(c)
	return err
}

// Apply never publishes an optimistic hash. The independent guardian can call
// it with the previous revision to compensate a failed or interrupted activation.
// Network rules are atomic; listener replacement is coordinated, not atomic.
func (e *Engine) Apply(ctx context.Context, revision configpoc.Revision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, target, err := e.compile(revision.Config)
	if err != nil || r.Hash != revision.Hash {
		return ErrState
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	data, exists, err := e.transport.Observe(ctx)
	if err != nil {
		e.current = nil
		return ErrState
	}
	// A fresh helper may only create a missing table in its newly owned namespace.
	// It cannot adopt or overwrite an existing table merely because of its name.
	if exists && !e.owned {
		return ErrState
	}
	if exists && e.current != nil {
		if _, err = localnft.VerifyObservation(data, e.artifact); err != nil {
			e.current = nil
			return ErrState
		}
	}
	batch := target.Create
	if exists {
		batch = target.Batch
	}
	if err = e.transport.Check(ctx, batch); err != nil {
		return err
	}
	e.current = nil
	// Mark ownership before apply: a lost acknowledgement must still permit the
	// guardian to restore its authorized previous revision in this same namespace.
	e.owned = true
	if err = e.transport.Apply(ctx, batch); err != nil {
		return err
	}
	if err = e.listeners.Apply(ctx, r); err != nil {
		return err
	}
	if _, err = e.observe(ctx, r, target); err != nil {
		return err
	}
	e.current, e.artifact = &r, target
	return nil
}

func (e *Engine) observe(ctx context.Context, r configpoc.Revision, a localnft.Artifact) (Observation, error) {
	data, exists, err := e.transport.Observe(ctx)
	if err != nil || !exists {
		return Observation{}, ErrState
	}
	rules, err := localnft.VerifyObservation(data, a)
	if err != nil {
		return Observation{}, ErrState
	}
	listeners, err := e.listeners.Observe(ctx)
	if err != nil {
		return Observation{}, ErrState
	}
	local := localpolicy.Observation{Revision: rules.Revision.Hash, Rules: append([]localpolicy.EffectiveRule{}, a.Rules...), Listeners: append([]localpolicy.Listener{}, listeners...)}
	reconciled, err := localpolicy.Reconcile(a.Revision.Config, local)
	if err != nil || !reconciled.Consistent {
		return Observation{}, ErrState
	}
	return Observation{Hash: r.Hash, Local: local}, nil
}

func (e *Engine) Observe(ctx context.Context) (Observation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current == nil {
		return Observation{}, ErrState
	}
	o, err := e.observe(ctx, *e.current, e.artifact)
	if err != nil {
		e.current = nil
	}
	return o, err
}

func (e *Engine) Current() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o, err := e.Observe(ctx)
	if err != nil {
		return ""
	}
	return o.Hash
}
