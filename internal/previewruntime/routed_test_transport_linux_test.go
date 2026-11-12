//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

// These transports simulate kernel/network I/O. Compilers, semantic readback,
// transactional storage, physical reserve files and group lease code are real.
type routedTestKernel struct {
	objects        map[routedactivation.Table][]map[string]any
	batches        [][]byte
	failAt, lostAt int
	readFail       bool
}

func (k *routedTestKernel) Check(ctx context.Context, data []byte) error {
	if ctx.Err() != nil || len(data) > routedactivation.MaxBatch {
		return routedactivation.ErrState
	}
	return nil
}
func routedTestTableID(name string) (routedactivation.Table, bool) {
	switch name {
	case firewallnft.TableName:
		return routedactivation.LegacyTable, true
	case routednft.TableName:
		return routedactivation.RoutedTable, true
	case localnft.TableName:
		return routedactivation.LocalTable, true
	}
	return 0, false
}
func (k *routedTestKernel) Apply(ctx context.Context, data []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	k.batches = append(k.batches, append([]byte{}, data...))
	call := len(k.batches)
	if k.failAt == call {
		return routedactivation.ErrState
	}
	var envelope struct {
		Commands []map[string]map[string]map[string]any `json:"nftables"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return routedactivation.ErrState
	}
	for _, command := range envelope.Commands {
		for verb, objects := range command {
			for kind, body := range objects {
				name, _ := body["table"].(string)
				if kind == "table" {
					name, _ = body["name"].(string)
				}
				table, ok := routedTestTableID(name)
				if !ok {
					return routedactivation.ErrState
				}
				if verb == "delete" && kind == "table" {
					delete(k.objects, table)
					continue
				}
				if verb != "add" {
					return routedactivation.ErrState
				}
				if kind == "rule" {
					for _, raw := range body["expr"].([]any) {
						expr := raw.(map[string]any)
						if _, ok := expr["counter"]; ok {
							expr["counter"] = map[string]any{"packets": 0, "bytes": 0}
						}
					}
				}
				k.objects[table] = append(k.objects[table], map[string]any{kind: body})
			}
		}
	}
	if k.lostAt == call {
		return routedactivation.ErrState
	}
	return nil
}
func (k *routedTestKernel) Observe(ctx context.Context, table routedactivation.Table) ([]byte, bool, error) {
	if k.readFail || ctx.Err() != nil {
		return nil, false, routedactivation.ErrState
	}
	objects, exists := k.objects[table]
	data, err := json.Marshal(map[string]any{"nftables": objects})
	return data, exists, err
}

type routedTestNetwork struct {
	snapshot networkexecutor.PreparedSnapshot
	active   bool
	calls    int
	before   func() error
	cancel   context.CancelFunc
	identity networkexecutor.OwnedNamespaceIdentity
}

func (n *routedTestNetwork) RecoverPrepared(ctx context.Context, revision networkplan.Revision, snapshot networkexecutor.PreparedSnapshot, original networkexecutor.OwnedNamespaceIdentity) error {
	if original != n.identity || ctx.Err() != nil || revision.Hash != n.snapshot.PlanHash || snapshot.Hash != n.snapshot.Hash {
		return routedactivation.ErrState
	}
	return nil
}

func (n *routedTestNetwork) Prepare(ctx context.Context, plan networkplan.Revision) (networkexecutor.PreparedSnapshot, error) {
	if n.active || ctx.Err() != nil || plan.Hash != n.snapshot.PlanHash {
		return networkexecutor.PreparedSnapshot{}, routedactivation.ErrState
	}
	return networkexecutor.CanonicalPreparedSnapshot(n.snapshot)
}
func (n *routedTestNetwork) VerifyPrepared(ctx context.Context, snapshot networkexecutor.PreparedSnapshot) error {
	a, err := networkexecutor.PreparedSnapshotBytes(n.snapshot)
	b, other := networkexecutor.PreparedSnapshotBytes(snapshot)
	if ctx.Err() != nil || n.active || err != nil || other != nil || !bytes.Equal(a, b) {
		return routedactivation.ErrState
	}
	return nil
}
func (n *routedTestNetwork) Verify(ctx context.Context) error {
	if !n.active || ctx.Err() != nil {
		return routedactivation.ErrState
	}
	return nil
}
func (n *routedTestNetwork) ApplyPrepared(ctx context.Context, plan networkplan.Revision, snapshot networkexecutor.PreparedSnapshot) error {
	if n.VerifyPrepared(ctx, snapshot) != nil || plan.Hash != snapshot.PlanHash {
		return routedactivation.ErrState
	}
	if n.before != nil && n.before() != nil {
		return routedactivation.ErrState
	}
	n.calls++
	n.active = true
	if n.cancel != nil {
		n.cancel()
	}
	return ctx.Err()
}
func (n *routedTestNetwork) RestorePrepared(ctx context.Context, snapshot networkexecutor.PreparedSnapshot) error {
	if ctx.Err() != nil || n.snapshot.Hash != snapshot.Hash {
		return routedactivation.ErrState
	}
	n.active = false
	return nil
}

type routedTestListeners struct {
	actual   []localpolicy.Listener
	failOnce bool
	calls    int
}

func (l *routedTestListeners) Apply(ctx context.Context, revision configpoc.Revision) error {
	l.calls++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	l.actual = nil
	for _, service := range revision.Config.LocalServices.Services {
		if service.Enabled {
			for _, binding := range service.Bindings {
				l.actual = append(l.actual, localpolicy.Listener{Owner: service.Owner, Service: service.ID, Interface: binding.Interface, LocalAddress: binding.LocalAddress, Protocol: service.Endpoints[0].Protocol, Port: service.Endpoints[0].FirstPort})
			}
		}
	}
	if l.failOnce {
		l.failOnce = false
		return routedactivation.ErrState
	}
	return nil
}
func (l *routedTestListeners) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return append([]localpolicy.Listener{}, l.actual...), nil
}
