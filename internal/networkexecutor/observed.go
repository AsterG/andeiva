package networkexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/AsterG/andeiva/internal/networkplan"
)

// ObservedSnapshot is actual empty-IPv4 inventory without a desired plan. It
// grants no L3 ownership and cannot authorize address/route writes or rollback.
// The initial no-network profile remains two owned links plus optional loopback.
type ObservedSnapshot struct {
	Version int             `json:"version"`
	Links   []SnapshotLink  `json:"links"`
	Routes  []SnapshotRoute `json:"routes"`
	Hash    string          `json:"hash"`
}

func (s ObservedSnapshot) observation() observation {
	return observation{Links: s.Links, Routes: s.Routes}
}

func CanonicalObservedSnapshot(input ObservedSnapshot) (ObservedSnapshot, error) {
	if input.Version != 1 || len(input.Hash) != 64 {
		return ObservedSnapshot{}, ErrScope
	}
	actual, err := canonicalEmptyObservation(input.observation())
	if err != nil {
		return ObservedSnapshot{}, err
	}
	snapshot := ObservedSnapshot{Version: 1, Links: actual.Links, Routes: actual.Routes}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > MaxPreparedSnapshot {
		return ObservedSnapshot{}, ErrScope
	}
	digest := sha256.Sum256(data)
	snapshot.Hash = hex.EncodeToString(digest[:])
	if snapshot.Hash != input.Hash {
		return ObservedSnapshot{}, ErrScope
	}
	return snapshot, nil
}

func ObservedSnapshotBytes(input ObservedSnapshot) ([]byte, error) {
	snapshot, err := CanonicalObservedSnapshot(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(snapshot)
}

// ObservedMatchesPrepared compares every normalized physical fact. Only the
// distinct document hashes and the prepared document's real PlanHash are omitted.
// This equality check is not authentication or authority to adopt resources.
func ObservedMatchesPrepared(observed ObservedSnapshot, prepared PreparedSnapshot) bool {
	actual, err := CanonicalObservedSnapshot(observed)
	if err != nil {
		return false
	}
	planned, err := CanonicalPreparedSnapshot(prepared)
	return err == nil && reflect.DeepEqual(actual.observation(), planned.observation())
}

// PrepareObserved receives physical bindings from authenticated supervisor
// inventory, never from an administrative body. No fabricated desired plan or
// sentinel plan hash is needed to capture a no-network Boot's actual baseline.
func (e *Executor) PrepareObserved(ctx context.Context, bindings []networkplan.Binding) (ObservedSnapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return ObservedSnapshot{}, err
	}
	if e.active != nil || len(bindings) != 2 {
		return ObservedSnapshot{}, ErrScope
	}
	expected := map[string]string{}
	for _, binding := range bindings {
		if !linkName.MatchString(binding.Name) || binding.Name == "lo" || expected[binding.Name] != "" || binding.HardwareAddress == "" {
			return ObservedSnapshot{}, ErrScope
		}
		expected[binding.Name] = binding.HardwareAddress
	}
	first, err := e.observe(ctx)
	if err != nil {
		return ObservedSnapshot{}, err
	}
	second, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return ObservedSnapshot{}, ErrObservation
	}
	for _, link := range first.Links {
		if link.Name != "lo" && expected[link.Name] != link.MAC {
			return ObservedSnapshot{}, ErrScope
		}
	}
	actual, err := canonicalEmptyObservation(first)
	if err != nil {
		return ObservedSnapshot{}, err
	}
	snapshot := ObservedSnapshot{Version: 1, Links: actual.Links, Routes: actual.Routes}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return ObservedSnapshot{}, err
	}
	digest := sha256.Sum256(data)
	snapshot.Hash = hex.EncodeToString(digest[:])
	return CanonicalObservedSnapshot(snapshot)
}

func (e *Executor) VerifyObserved(ctx context.Context, snapshot ObservedSnapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return err
	}
	if e.active != nil {
		return ErrScope
	}
	canonical, err := CanonicalObservedSnapshot(snapshot)
	if err != nil {
		return err
	}
	actual, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(actual, canonical.observation()) {
		return ErrObservation
	}
	return nil
}

// RecoverObserved verifies authenticated same-incarnation work without ever
// reconstructing a managed transaction. The scope/provenance contract is the
// same as RecoverPrepared; only NewInOwnedNamespace can supply that capability.
func (e *Executor) RecoverObserved(ctx context.Context, snapshot ObservedSnapshot, original OwnedNamespaceIdentity) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return err
	}
	if e.identity == nil || *e.identity != original || e.active != nil {
		return ErrScope
	}
	canonical, err := CanonicalObservedSnapshot(snapshot)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		actual, err := e.observe(ctx)
		if err != nil || !reflect.DeepEqual(actual, canonical.observation()) {
			e.fenced = true
			return ErrUncertain
		}
	}
	return nil
}
