package routednft

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/nftengine"
)

// Adapter is internal laboratory control, deliberately separate from configpoc
// and public DTOs. The caller supplies a trusted fixed-namespace transport and
// complete baseline; neither comments nor an arbitrary observed hash bootstrap it.
type Adapter struct {
	mu        sync.Mutex
	transport nftengine.Transport
	known     []Revision
}

func NewAdapter(t nftengine.Transport, baseline Revision) (*Adapter, error) {
	r, e := Canonical(baseline.Policy)
	if e != nil || r.Hash != baseline.Hash || t == nil {
		return nil, ErrPolicy
	}
	return &Adapter{transport: t, known: []Revision{r}}, nil
}
func (a *Adapter) observe(ctx context.Context) (Observation, error) {
	data, e := a.transport.Observe(ctx)
	if e != nil {
		return Observation{}, nftengine.ErrTransport
	}
	for _, r := range a.known {
		if o, e := VerifyObservation(data, r); e == nil {
			return o, nil
		}
	}
	return Observation{}, nftengine.ErrDrift
}
func (a *Adapter) Inspect(parent context.Context) (Observation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	o, e := a.observe(ctx)
	if e == nil {
		a.known = []Revision{o.Revision}
	}
	return o, e
}
func (a *Adapter) Apply(parent context.Context, target Revision) error {
	artifact, e := Compile(target.Policy)
	if e != nil || artifact.Revision.Hash != target.Hash {
		return ErrPolicy
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	previous, e := a.observe(ctx)
	if e != nil {
		return e
	}
	a.known = []Revision{previous.Revision}
	if previous.Revision.Hash == target.Hash {
		return nil
	}
	if a.transport.Check(ctx, artifact.Batch) != nil {
		return nftengine.ErrTransport
	}
	a.known = append(a.known, artifact.Revision)
	applyErr := a.transport.Apply(ctx, artifact.Batch)
	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	observed, e := a.observe(readCtx)
	if e != nil {
		return e
	}
	a.known = []Revision{observed.Revision}
	if applyErr != nil || observed.Revision.Hash != target.Hash {
		return nftengine.ErrTransport
	}
	return nil
}
