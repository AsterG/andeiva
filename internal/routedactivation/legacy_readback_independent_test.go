package routedactivation

import (
	"context"
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
)

// These fixtures exercise adapter contracts only; they do not attest a kernel.
type independentLegacyCapture struct {
	Kernel
	read func(context.Context, Table) ([]byte, bool, error)
}

func (k independentLegacyCapture) Observe(ctx context.Context, table Table) ([]byte, bool, error) {
	return k.read(ctx, table)
}

func TestIndependentLegacyReadbackRejectsAmbiguousAbsence(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		err  error
	}{
		{"error_without_body", nil, errors.New("unavailable")},
		{"error_with_body", []byte(`{"nftables":[]}`), errors.New("unavailable")},
		{"successful_absence_with_residual_body", []byte(`{"nftables":[]}`), nil},
		{"oversized_absence", make([]byte, MaxBatch+1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := assembleFixture(t)
			defer f.group.Close()
			f.engine.kernel = independentLegacyCapture{Kernel: f.kernel, read: func(context.Context, Table) ([]byte, bool, error) {
				return tc.body, false, tc.err
			}}
			if _, _, _, err := f.engine.ObserveLegacy(context.Background()); err == nil {
				t.Fatal("ambiguous capture was published as verified absence")
			}
		})
	}
}

func TestIndependentLegacyReadbackRejectsUnselectedDisabledPolicy(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	ctx := context.Background()
	known := f.engine.options.Legacy
	changed := known.Config
	disabled := false
	changed.Rules = append(append([]configpoc.Rule(nil), changed.Rules...), configpoc.Rule{
		ID: "not-selected", Action: "allow", Enabled: &disabled,
		Match: &configpoc.Match{Source: "192.0.2.0/24", Destination: "198.51.100.0/24", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 443, To: 443}},
	})
	foreign, err := configpoc.Canonical(changed)
	if err != nil || foreign.Hash == known.Hash {
		t.Fatal("invalid independent revision fixture", err)
	}
	artifact, err := firewallnft.Compile(foreign.Config)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.kernel.objects, LegacyTable)
	if err = f.kernel.Apply(ctx, artifact.Create); err != nil {
		t.Fatal(err)
	}
	data, present, err := f.kernel.Observe(ctx, LegacyTable)
	if err != nil || !present {
		t.Fatal("fixture table missing", err)
	}
	if _, err = firewallnft.VerifyObservation(data, foreign); err != nil {
		t.Fatal("fixture is not a valid full schema-4 projection", err)
	}
	if _, _, _, err = f.engine.ObserveLegacy(ctx); err == nil {
		t.Fatal("unselected disabled configuration adopted from kernel metadata")
	}
}
