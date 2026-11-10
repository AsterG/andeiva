// Package localtransport confines nft execution to an owned laboratory namespace.
package localtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/localnft"
)

const (
	CommandTimeout = 3 * time.Second
	MaxOutput      = localnft.MaxObservation
	maxTables      = 64
)

var (
	ErrIdentity    = errors.New("local_transport_identity")
	ErrInput       = errors.New("local_transport_input")
	ErrCommand     = errors.New("local_transport_command")
	ErrObservation = errors.New("local_transport_observation")
	ErrPlatform    = errors.New("local_transport_platform")
)

type operation uint8

const (
	check operation = iota
	apply
	listTables
	listTable
)

type executor func(context.Context, operation, []byte) ([]byte, error)

type Transport struct {
	mu      sync.Mutex
	execute executor
	guard   func() error
	checked [32]byte
	permit  bool
}

// Check grants one use of these exact checked bytes. It is not an authorization
// API: only the typed localengine compiler may supply batches to this transport.
func (t *Transport) Check(ctx context.Context, batch []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.permit = false
	if ctx == nil || len(batch) == 0 || len(batch) > localnft.MaxBatch {
		return ErrInput
	}
	copy := bytes.Clone(batch)
	if validateBatch(copy) != nil {
		return ErrInput
	}
	if t.guard == nil || t.execute == nil || t.guard() != nil {
		return ErrIdentity
	}
	if _, err := t.run(ctx, check, copy); err != nil {
		return err
	}
	t.checked = sha256.Sum256(copy)
	t.permit = true
	return nil
}

func (t *Transport) Apply(ctx context.Context, batch []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	allowed := t.permit
	t.permit = false
	if ctx == nil || !allowed || len(batch) == 0 || len(batch) > localnft.MaxBatch {
		return ErrInput
	}
	copy := bytes.Clone(batch)
	if validateBatch(copy) != nil || sha256.Sum256(copy) != t.checked {
		return ErrInput
	}
	if t.guard == nil || t.execute == nil || t.guard() != nil {
		return ErrIdentity
	}
	_, err := t.run(ctx, apply, copy)
	return err
}

// Observe reports absence only after a valid, successful kernel table listing.
// A vanished table between the two reads is an error, never proof of absence.
func (t *Transport) Observe(ctx context.Context) ([]byte, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.permit = false
	if ctx == nil {
		return nil, false, ErrInput
	}
	if t.guard == nil || t.execute == nil || t.guard() != nil {
		return nil, false, ErrIdentity
	}
	data, err := t.run(ctx, listTables, nil)
	if err != nil {
		return nil, false, err
	}
	exists, err := tableExists(data)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	data, err = t.run(ctx, listTable, nil)
	if err != nil {
		return nil, false, err
	}
	if err := validateListing(data); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (t *Transport) run(parent context.Context, op operation, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, CommandTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrCommand, err)
	}
	data, err := t.execute(ctx, op, input)
	if err != nil {
		return nil, errors.Join(ErrCommand, ctx.Err())
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrCommand, ctx.Err())
	}
	if len(data) > MaxOutput {
		return nil, ErrObservation
	}
	if t.guard() != nil {
		return nil, ErrIdentity
	}
	return bytes.Clone(data), nil
}
