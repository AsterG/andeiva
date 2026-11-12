package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftengine"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

type policyAdapter interface {
	Apply(context.Context, routednft.Revision) error
	Inspect(context.Context) (routednft.Observation, error)
}

func enableFixtureForwarding(ctx context.Context, gateway *namespace) error {
	for _, assignment := range []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"} {
		if _, err := gateway.exec(ctx, nil, "/usr/sbin/sysctl", "-q", "-w", assignment); err != nil {
			return err
		}
	}
	return nil
}

type groupKernel struct{ transport }

func groupTableName(table routedactivation.Table) (string, error) {
	switch table {
	case routedactivation.LegacyTable:
		return firewallnft.TableName, nil
	case routedactivation.RoutedTable:
		return routednft.TableName, nil
	case routedactivation.LocalTable:
		return localnft.TableName, nil
	default:
		return "", errLab
	}
}

func tablePresent(data []byte, name string) (bool, error) {
	if len(data) == 0 || len(data) > routednft.MaxObservation || !jsoncheck.UniqueFields(data) {
		return false, errLab
	}
	var envelope struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.Objects == nil || len(envelope.Objects) > 16 {
		return false, errLab
	}
	found := false
	for i, object := range envelope.Objects {
		if len(object) != 1 {
			return false, errLab
		}
		if meta, ok := object["metainfo"]; ok && i == 0 {
			var metadata map[string]any
			decoder := json.NewDecoder(bytes.NewReader(meta))
			decoder.UseNumber()
			if decoder.Decode(&metadata) != nil || len(metadata) != 3 || metadata["version"] == nil || metadata["release_name"] == nil || metadata["json_schema_version"] == nil || !nftengine.ValidMetainfo(metadata) {
				return false, errLab
			}
			continue
		}
		raw, ok := object["table"]
		if !ok {
			return false, errLab
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		// Additional kernel table metadata does not establish authority. Complete
		// rules are independently verified after this successful presence query.
		if json.Unmarshal(raw, &table) != nil || table.Family == "" || table.Name == "" {
			return false, errLab
		}
		if table.Family == "inet" && table.Name == name {
			if found {
				return false, errLab
			}
			found = true
		}
	}
	return found, nil
}

func (k groupKernel) Observe(ctx context.Context, table routedactivation.Table) ([]byte, bool, error) {
	name, err := groupTableName(table)
	if err != nil || k.bindingCheck(ctx) != nil {
		return nil, false, errLab
	}
	listing, err := k.gateway.exec(ctx, nil, nftPath, "-j", "list", "tables")
	if err != nil {
		return nil, false, err
	}
	present, err := tablePresent(listing, name)
	if err != nil || !present {
		return nil, false, err
	}
	data, err := k.gateway.exec(ctx, nil, nftPath, "-j", "-n", "-y", "list", "table", "inet", name)
	return data, true, err
}

// This fixture deliberately starts no managed gateway listeners. It verifies the
// actual isolated gateway socket tables; it never reads/stops host SSH or HTTPS.
type groupEmptyListeners struct{ transport }

func (l groupEmptyListeners) Apply(ctx context.Context, revision configpoc.Revision) error {
	r, err := configpoc.Canonical(revision.Config)
	if err != nil || r.Hash != revision.Hash || r.Config.SchemaVersion != 3 || r.Config.LocalServices == nil || len(r.Config.LocalServices.Services) != 0 {
		return errLab
	}
	_, err = l.Observe(ctx)
	return err
}
func (l groupEmptyListeners) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	if l.bindingCheck(ctx) != nil {
		return nil, errLab
	}
	data, err := l.gateway.exec(ctx, nil, l.self, "--group-listeners-empty")
	if err != nil || string(data) != "EMPTY\n" {
		return nil, errors.Join(errLab, err)
	}
	return []localpolicy.Listener{}, nil
}

func emptySocketTable(data []byte) bool {
	if len(data) == 0 || len(data) > 64<<10 {
		return false
	}
	rows := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, line)
		}
	}
	return len(rows) == 1 && strings.Contains(rows[0], "local_address") && strings.Contains(rows[0], "inode") && strings.Fields(rows[0])[0] == "sl"
}

func verifyEmptyGatewaySockets() error {
	root, err := os.OpenRoot("/proc/self/net")
	if err != nil {
		return err
	}
	defer root.Close()
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		file, err := root.Open(table)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 64<<10+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 64<<10 || !emptySocketTable(data) {
			return errors.Join(errLab, readErr, closeErr)
		}
	}
	fmt.Println("EMPTY")
	return nil
}

type groupSelection struct {
	plan              configpoc.RoutedTransitionV1
	previous          *configpoc.RoutedActivationBundleV1
	target            configpoc.RoutedActivationBundleV1
	prepared          routedactivation.PreparationV1
	started, deadline time.Time
	leaseID           string
}

type groupLab struct {
	kernel    groupKernel
	network   *networkexecutor.Executor
	legacy    configpoc.Revision
	local     configpoc.Revision
	engine    *routedactivation.Engine
	group     *nftguardian.Group
	selection groupSelection
	current   configpoc.RoutedActivationBundleV1
	counter   int
}

func labReference(operation, role string, value []byte) string {
	sum := sha256.Sum256(append([]byte(operation+"\x00"+role+"\x00"), value...))
	return hex.EncodeToString(sum[:])
}

func newGroupLab(ctx context.Context, network *networkexecutor.Executor, t transport) (*groupLab, error) {
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		return nil, err
	}
	localConfig := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{
		{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}},
		{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}},
	}, Services: []localpolicy.Service{}}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
	if err != nil {
		return nil, err
	}
	b := &groupLab{kernel: groupKernel{t}, network: network, legacy: legacy, local: local}
	// Establish the actual trusted supervisor deny baseline before forwarding.
	artifact, err := firewallnft.Compile(legacy.Config)
	if err != nil || t.Check(ctx, artifact.Create) != nil || t.Apply(ctx, artifact.Create) != nil {
		return nil, errLab
	}
	if err := b.cold(ctx); err != nil {
		_ = b.Close()
		return nil, err
	}
	return b, nil
}

func (b *groupLab) resolve(ctx context.Context, plan configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) (routedactivation.PreparationV1, error) {
	s := b.selection
	if ctx.Err() != nil || plan != s.plan || target.Composite.Hash != s.target.Composite.Hash || !deadline.Equal(s.deadline) || !s.deadline.Equal(s.started.Add(30*time.Second)) || (previous == nil) != (s.previous == nil) || (previous != nil && previous.Composite.Hash != s.previous.Composite.Hash) {
		return routedactivation.PreparationV1{}, errLab
	}
	// This is a bounded trusted fixture record, not production persistence or
	// a substitute for the coordinator's selected Intent/G1/R2 validation.
	return s.prepared, nil
}

func (b *groupLab) selectTarget(ctx context.Context, target configpoc.RoutedActivationBundleV1, previous *configpoc.RoutedActivationBundleV1) error {
	prepared, err := b.engine.Prepare(ctx, target)
	if err != nil {
		return err
	}
	b.counter++
	operation := fmt.Sprintf("group-lab-%d", b.counter)
	before, err := routedactivation.OwnedBytes(prepared.Before)
	if err != nil {
		return err
	}
	after, err := routedactivation.OwnedBytes(prepared.Target)
	if err != nil {
		return err
	}
	deps, err := routedactivation.DependenciesBytes(prepared.Dependencies)
	if err != nil {
		return err
	}
	started := time.Now().UTC()
	plan := configpoc.RoutedTransitionV1{Version: 1, Operation: operation,
		Previous: labReference(operation, "previous-snapshot", before), Target: labReference(operation, "target-snapshot", after),
		BeforeOwned: labReference(operation, "before-owned", before), TargetOwned: labReference(operation, "target-owned", after), Dependencies: labReference(operation, "dependencies", deps)}
	b.selection = groupSelection{plan, previous, target, prepared, started, started.Add(30 * time.Second), fmt.Sprintf("group-lease-%d", b.counter)}
	return nil
}

func (b *groupLab) cold(ctx context.Context) error {
	engine, err := routedactivation.New(b.kernel, b.network, groupEmptyListeners{b.kernel.transport}, routedactivation.Options{Legacy: b.legacy, ResolvePlan: b.resolve})
	if err != nil {
		return err
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		return err
	}
	b.engine, b.group = engine, group
	policy := routednft.LabPolicy()
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		return err
	}
	target, err := configpoc.NewRoutedActivationBundleV1(firewall, b.local)
	if err != nil || b.selectTarget(ctx, target, nil) != nil {
		return errLab
	}
	s := b.selection
	if err := group.ArmBootstrapUntilLease(ctx, s.plan, s.leaseID, target, s.deadline); err != nil {
		return err
	}
	state, current, err := group.SnapshotObserved()
	if err != nil || current != "" || state.Previous != "" || state.ID != s.leaseID || state.ID == s.plan.Operation {
		return errLab
	}
	if err := group.ApplyLease(ctx, s.plan, target, state); err != nil {
		return err
	}
	b.current = target
	return nil
}

func (b *groupLab) Inspect(ctx context.Context) (routednft.Observation, error) {
	_, hash, err := b.group.SnapshotObserved()
	if err != nil || hash != b.current.Composite.Hash {
		return routednft.Observation{}, errLab
	}
	data, exists, err := b.kernel.Observe(ctx, routedactivation.RoutedTable)
	if err != nil || !exists {
		return routednft.Observation{}, errLab
	}
	revision, err := routednft.Canonical(*b.current.Firewall.Config.Routed)
	if err != nil {
		return routednft.Observation{}, err
	}
	return routednft.VerifyObservation(data, revision)
}

func (b *groupLab) Apply(ctx context.Context, revision routednft.Revision) error {
	if err := b.armApply(ctx, revision); err != nil {
		return err
	}
	state, _, err := b.group.SnapshotObserved()
	if err != nil {
		return err
	}
	return b.group.ConfirmLease(ctx, b.selection.plan, state)
}

func (b *groupLab) armApply(ctx context.Context, revision routednft.Revision) error {
	canonical, err := routednft.Canonical(revision.Policy)
	if err != nil || canonical.Hash != revision.Hash {
		return errLab
	}
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &canonical.Policy})
	if err != nil {
		return err
	}
	target, err := configpoc.NewRoutedActivationBundleV1(firewall, b.local)
	if err != nil {
		return err
	}
	previous := b.current
	if err := b.selectTarget(ctx, target, &previous); err != nil {
		return err
	}
	s := b.selection
	if b.group.ArmUntilLease(ctx, s.plan, s.leaseID, previous, target, s.deadline) != nil {
		return errLab
	}
	state, _, err := b.group.SnapshotObserved()
	if err != nil || b.group.ApplyLease(ctx, s.plan, target, state) != nil {
		return errLab
	}
	b.current = target
	return nil
}

func (b *groupLab) qualifyColdRecoveryAndConfirm(ctx context.Context, lan *namespace) error {
	for _, mode := range []string{"--probe-tcp", "--probe-udp"} {
		out, err := lan.exec(ctx, nil, b.kernel.self, mode)
		if err != nil || !strings.HasPrefix(string(out), "198.19.0.1:") {
			return errLab
		}
	}
	s := b.selection
	state, _, err := b.group.SnapshotObserved()
	if err != nil || b.group.RecoverLease(s.plan, state) != nil || b.network.VerifyPrepared(ctx, s.prepared.Dependencies.Prepared) != nil || b.engine.MatchOwned(ctx, s.plan.BeforeOwned) != nil {
		return errLab
	}
	fmt.Println("PASS typed group TCP/UDP SNAT and exact cold recovery")
	if b.group.Close() != nil || b.cold(ctx) != nil {
		return errLab
	}
	state, _, err = b.group.SnapshotObserved()
	if err != nil {
		return err
	}
	wrong := state
	wrong.Deadline = wrong.Deadline.Add(time.Nanosecond)
	if b.group.ConfirmLease(ctx, b.selection.plan, wrong) == nil || b.group.ConfirmLease(ctx, b.selection.plan, state) != nil || b.group.ConfirmLease(ctx, b.selection.plan, state) != nil {
		return errLab
	}
	fmt.Println("PASS typed group distinct confirmed lease and exact lost-confirm reconciliation")
	return nil
}

func (b *groupLab) qualifyExpiry(ctx context.Context, lan *namespace) error {
	previous := b.current
	revision, err := routednft.Canonical(routednft.LabPolicy())
	if err != nil || b.armApply(ctx, revision) != nil {
		return errLab
	}
	s := b.selection
	state, _, err := b.group.SnapshotObserved()
	if err != nil {
		return err
	}
	if _, err := lan.exec(ctx, nil, b.kernel.self, "--probe-tcp"); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(s.deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	// Snapshot serializes with the bounded timer compensation; it cannot claim
	// completion from a cached target or a request-relative replacement window.
	readbackDeadline := time.Now().Add(4 * time.Second)
	for {
		observed, hash, err := b.group.SnapshotObserved()
		if err == nil && observed.Phase == "expired" && hash == previous.Composite.Hash {
			break
		}
		if time.Now().After(readbackDeadline) {
			return errLab
		}
		poll := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			poll.Stop()
			return ctx.Err()
		case <-poll.C:
		}
	}
	if b.group.RecoverLease(s.plan, state) != nil {
		return errLab
	}
	b.current = previous
	if _, err := lan.exec(ctx, nil, b.kernel.self, "--probe-tcp"); err == nil {
		return errors.New("expired group policy still authorized forwarding")
	}
	fmt.Println("PASS typed group original confirmed deadline expired and exact previous policy recovered")
	return nil
}

func (b *groupLab) Close() error {
	if b == nil || b.group == nil {
		return nil
	}
	return b.group.Close()
}
