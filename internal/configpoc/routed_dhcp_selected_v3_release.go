package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// VerifyDHCPReleasedV3 proves that terminal retirement is selected before the
// helper releases its WAN transaction lane back to the selected Boot adapter.
func (r *RoutedSelectionReaderV2) VerifyDHCPReleasedV3(ctx context.Context) (result error) {
	if r == nil {
		return ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			result = ErrRecovery
		}
	}()
	if v.store.state.RoutedDHCP != nil || validateRoutedDHCPSelectedV3(v.store.state, v.store.readObject) != nil {
		return ErrRecovery
	}
	return r.revalidate(ctx, v)
}

// LastWithdrawnDHCPV3 returns only an archived, selected terminal witness for
// this exact namespace incarnation. It never confers permission to reuse a
// token; a new boot/run has no prior gate in its newly owned namespace.
func (r *RoutedSelectionReaderV2) LastWithdrawnDHCPV3(ctx context.Context) (out *networkexecutor.LeaseSelectedSnapshotV3, result error) {
	if r == nil {
		return nil, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = nil
			result = ErrRecovery
		}
	}()
	if v.store.state.RoutedDHCP != nil || validateRoutedDHCPSelectedV3(v.store.state, v.store.readObject) != nil {
		return nil, ErrRecovery
	}
	if last := v.store.state.RoutedDHCPLast; last != "" {
		var terminal v3RoutedDHCPState
		if v.store.readObject(last, &terminal) != nil || validateRoutedDHCPTerminalV3(terminal, v.store.state.Lineage, v.store.readObject) != nil {
			return nil, ErrRecovery
		}
		w, e := loadRoutedDHCPWorkV3(terminal.Work, v.store.state.Lineage, v.store.readObject)
		if e != nil {
			return nil, e
		}
		if w.Snapshot.Identity == r.options.Identity {
			s := clone(w.Snapshot)
			out = &s
		}
	}
	if err = r.revalidate(ctx, v); err != nil {
		return nil, err
	}
	return out, nil
}
