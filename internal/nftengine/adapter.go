package nftengine

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// Transport is implemented only by the laboratory's fixed-target helper. Its
// methods must enforce namespace identity, command/output bounds and deadlines.
// It is not a public API accepting caller-selected nft input.
type Transport interface {
	Check(context.Context, []byte) error
	Apply(context.Context, []byte) error
	Observe(context.Context) ([]byte, error)
}

type Engine struct {
	mu             sync.Mutex
	transport      Transport
	compile        func(configpoc.Config) (Artifact, error)
	decode         func([]byte) (configpoc.Revision, error)
	name           string
	expected       string
	uncertain      bool
	before, target string
}

var _ configpoc.Engine = (*Engine)(nil)

func New(name string, transport Transport, compile func(configpoc.Config) (Artifact, error), decode func([]byte) (configpoc.Revision, error)) *Engine {
	return &Engine{transport: transport, name: name, compile: compile, decode: decode}
}
func (e *Engine) Name() string { return e.name }

func (e *Engine) Validate(config configpoc.Config) error {
	artifact, err := e.compile(config)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.transport == nil {
		return ErrTransport
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if e.transport.Check(ctx, artifact.Batch) != nil {
		return ErrTransport
	}
	return nil
}

func (e *Engine) observe(ctx context.Context) (configpoc.Revision, error) {
	if e.transport == nil {
		return configpoc.Revision{}, ErrTransport
	}
	data, err := e.transport.Observe(ctx)
	if err != nil {
		return configpoc.Revision{}, ErrTransport
	}
	return e.decode(data)
}

func (e *Engine) Current() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	revision, err := e.observe(ctx)
	if err != nil || (e.uncertain && !e.knownOutcome(revision.Hash)) || (!e.uncertain && e.expected != "" && revision.Hash != e.expected) {
		return ""
	}
	e.expected = revision.Hash
	e.uncertain = false
	return revision.Hash
}

func (e *Engine) knownOutcome(hash string) bool {
	return hash == e.before || hash == e.target
}

func (e *Engine) Apply(parent context.Context, revision configpoc.Revision) error {
	artifact, err := e.compile(revision.Config)
	if err != nil || artifact.Revision.Hash != revision.Hash {
		return ErrPolicy
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	if e.uncertain && !e.knownOutcome(revision.Hash) {
		return ErrDrift
	}
	previous, err := e.observe(ctx)
	if err != nil {
		return err
	}
	// Independent deadline enforcement may already have restored this exact
	// revision. A verified no-op is safe and permits the journal to reconcile.
	if previous.Hash == revision.Hash {
		e.expected = previous.Hash
		e.uncertain = false
		return nil
	}
	if (e.uncertain && !e.knownOutcome(previous.Hash)) || (!e.uncertain && e.expected != "" && previous.Hash != e.expected) {
		return ErrDrift
	}
	e.expected = previous.Hash
	if err := e.transport.Check(ctx, artifact.Batch); err != nil {
		return ErrTransport
	}
	e.before, e.target, e.uncertain = previous.Hash, revision.Hash, true
	applyErr := e.transport.Apply(ctx, artifact.Batch)
	// A failed response can follow a successful kernel transaction. Observe using
	// an independent bounded context so the coordinator can compensate this state.
	readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer readCancel()
	observed, readErr := e.observe(readCtx)
	if readErr != nil {
		return readErr
	}
	if observed.Hash != previous.Hash && observed.Hash != revision.Hash {
		return ErrDrift
	}
	e.expected = observed.Hash
	e.uncertain = false
	if applyErr != nil || observed.Hash != revision.Hash {
		return ErrTransport
	}
	return nil
}
