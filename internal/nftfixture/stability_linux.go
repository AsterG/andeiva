package nftfixture

import (
	"bytes"
	"context"
	"errors"
	"time"
)

const hostQuietWindow = 10 * time.Second
const hostStabilityLimit = 30 * time.Second

var errHostUnstable = errors.New("ANDEIVA_NFT_HOST_NOT_STABLE")

// A quiet startup window accommodates delayed laboratory DHCP configuration.
// It is a bounded heuristic, not proof that network configuration has finished.
// Its last snapshot becomes the fixed baseline; live checks never reset it.
func waitStableHost(parent context.Context, read func(context.Context) (map[string][]byte, error), now func() time.Time, wait func(context.Context) error) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(parent, hostStabilityLimit)
	defer cancel()
	started := now()
	var last map[string][]byte
	var stableSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(errHostUnstable, err)
		}
		if now().Sub(started) >= hostStabilityLimit {
			return nil, errHostUnstable
		}
		snapshot, err := read(ctx)
		if err != nil {
			return nil, errors.Join(errHostUnstable, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(errHostUnstable, err)
		}
		observed := now()
		if observed.Sub(started) >= hostStabilityLimit || len(snapshot) == 0 {
			return nil, errHostUnstable
		}
		if last == nil || !sameHostSnapshot(last, snapshot) {
			stableSince = observed
		}
		last = copyHostSnapshot(snapshot)
		if observed.Sub(stableSince) >= hostQuietWindow {
			return last, nil
		}
		if err := wait(ctx); err != nil {
			return nil, errors.Join(errHostUnstable, err)
		}
	}
}

func sameHostSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		other, ok := b[key]
		if !ok || !bytes.Equal(value, other) {
			return false
		}
	}
	return true
}

func copyHostSnapshot(snapshot map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(snapshot))
	for key, value := range snapshot {
		copy[key] = bytes.Clone(value)
	}
	return copy
}

func waitSnapshotInterval(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
