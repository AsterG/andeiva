package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// RoutedDHCPConfigurationSelectedV4 is read evidence, not a grant or an
// acquisition capability. Original undo metadata and current configuration
// metadata are intentionally distinct; runtime factories do not consume it yet.
type RoutedDHCPConfigurationSelectedV4 struct {
	original          v3RoutedDHCPWork
	ref               SelectionReferenceV2
	currentRunning    string
	currentGeneration uint64
}

func (s RoutedDHCPConfigurationSelectedV4) Reference() SelectionReferenceV2 { return s.ref }
func (s RoutedDHCPConfigurationSelectedV4) OriginalRunning() string         { return s.original.Running }
func (s RoutedDHCPConfigurationSelectedV4) OriginalGeneration() uint64      { return s.original.Generation }
func (s RoutedDHCPConfigurationSelectedV4) CurrentRunning() string          { return s.currentRunning }
func (s RoutedDHCPConfigurationSelectedV4) CurrentGeneration() uint64       { return s.currentGeneration }
func (s RoutedDHCPConfigurationSelectedV4) Epoch() uint64                   { return s.original.Epoch }
func (s RoutedDHCPConfigurationSelectedV4) Snapshot() networkexecutor.LeaseSelectedSnapshotV3 {
	return clone(s.original.Snapshot)
}

// ResolveDHCPConfigurationCurrentV4 resolves only the selected exact original
// Work. No proof escapes before the final selector/pool/provenance validation.
func (r *RoutedSelectionReaderV2) ResolveDHCPConfigurationCurrentV4(ctx context.Context, expected string) (out RoutedDHCPConfigurationSelectedV4, result error) {
	if r == nil || !validHash(expected) {
		return out, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.readCandidateWithGateV2(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedDHCPConfigurationSelectedV4{}
			result = ErrRecovery
		}
	}()
	st := v.store.state
	if st.RoutedDHCPConfiguration == nil || st.RoutedDHCP == nil || st.RoutedDHCP.Work != expected || validateRoutedDHCPConfigurationSelectionV4(st.RoutedDHCPConfiguration, st, v.store.readObject, v.store.lookupRetained, routedDHCPConfigurationHeaderV4) != nil {
		return out, ErrRecovery
	}
	work, err := loadRoutedDHCPWorkV3(expected, st.Lineage, v.store.readObject)
	if err != nil || work.Snapshot.Identity != r.options.Identity {
		return out, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return out, err
	}
	ref := v.ref
	ref.Mode, ref.WorkHash = "dhcp-configuration-v4", expected
	return RoutedDHCPConfigurationSelectedV4{original: work, ref: ref, currentRunning: st.Configuration.Running.Hash, currentGeneration: st.Generation}, nil
}
