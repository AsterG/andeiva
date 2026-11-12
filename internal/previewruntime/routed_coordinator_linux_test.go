//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

func routedCoordinatorRoot(t *testing.T) *os.Root {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

type routedBootReplyLostFixture struct {
	*RoutedAuthority
	lose bool
}

func (a *routedBootReplyLostFixture) Bootstrap(ctx context.Context, p configpoc.RoutedSelectedPlanV1, started time.Time) error {
	if err := a.RoutedAuthority.Bootstrap(ctx, p, started); err != nil {
		return err
	}
	if a.lose {
		a.lose = false
		return configpoc.ErrInterrupted
	}
	return nil
}

func TestRoutedPhysicalCoordinatorConfirmedLifecycle(t *testing.T) {
	routedPhysicalCoordinatorLifecycle(t, false)
}

func TestRoutedPhysicalCoordinatorNoNetworkBootLifecycle(t *testing.T) {
	routedPhysicalCoordinatorLifecycle(t, true)
}

func routedPhysicalCoordinatorLifecycle(t *testing.T, noNetworkBoot bool) {
	ctx := context.Background()
	policy := routednft.LabPolicy()
	localConfig := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{
		{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}},
		{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}},
	}, Services: []localpolicy.Service{}}
	enabled := true
	retained := []configpoc.Rule{
		{ID: "retained-tcp", Enabled: &enabled, Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}},
		{ID: "retained-udp", Enabled: &enabled, Action: "deny", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "udp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18081, To: 18081}}},
	}
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: retained})
	if err != nil {
		t.Fatal(err)
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
	if err != nil {
		t.Fatal(err)
	}
	areas := [3]*os.Root{routedCoordinatorRoot(t), routedCoordinatorRoot(t), routedCoordinatorRoot(t)}
	engines := []*configpoc.SimEngine{configpoc.NewSimEngine("legacy-firewall"), configpoc.NewSimEngine("legacy-local")}
	var fingerprints [2]configpoc.LegacyFingerprintV2
	for i, item := range []struct {
		domain   string
		revision configpoc.Revision
	}{{"firewall", legacy}, {"local_services", local}} {
		old, e := configpoc.Open(areas[i].Name(), []configpoc.Engine{engines[i]}, configpoc.Options{Initial: &item.revision.Config})
		if e != nil {
			t.Fatal(e)
		}
		if e = old.Close(); e != nil {
			t.Fatal(e)
		}
		fingerprints[i], e = configpoc.InspectLegacyV2(areas[i], item.domain)
		if e != nil {
			t.Fatal(e)
		}
	}
	subject, err := configpoc.NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	revision := sha256.Sum256([]byte("fixture credential incarnation"))
	revisionHash := hex.EncodeToString(revision[:])
	auth, err := adminauth.New([]adminauth.Account{{Username: "operator", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: subject, CredentialRevision: revisionHash}}, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	budget := configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}
	if err = configpoc.PrepareMigrationV2(areas[2], areas[0], areas[1], fingerprints, []configpoc.SubjectV2{{ID: subject, Login: "operator", CredentialRevision: revisionHash}}, nil, budget, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var pools configpoc.RuntimePoolsV2
	for _, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
		out      **recoveryreserve.PoolV2
	}{{recoveryreserve.AdmissionV2, 4096, &pools.Admission}, {recoveryreserve.PlanV2, 16384, &pools.Plan}, {recoveryreserve.EmergencyV2, 8192, &pools.Emergency}} {
		p, e := recoveryreserve.PrepareV2(routedCoordinatorRoot(t), 18, item.capacity, item.role)
		if e != nil {
			t.Fatal(e)
		}
		*item.out = p
		t.Cleanup(func() { _ = p.Close() })
	}
	service, err := configpoc.OpenServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.PrepareRuntimeReservesV2(ctx, pools); err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: policy.Network.Hash, Links: []networkexecutor.SnapshotLink{{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}, {Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{}}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	snapshot.Hash = hex.EncodeToString(sum[:])
	identity := networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Namespace: 22, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: "0123456789abcdef0123456789abcdef"}
	kernel := &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
	compiled, err := firewallnft.Compile(legacy.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err = kernel.Apply(ctx, compiled.Create); err != nil {
		t.Fatal(err)
	}
	network := &routedTestNetwork{snapshot: snapshot, identity: identity}
	engineOptions := routedactivation.Options{Legacy: legacy}
	for _, link := range snapshot.Links {
		engineOptions.ObservedBindings = append(engineOptions.ObservedBindings, networkplan.Binding{Name: link.Name, HardwareAddress: link.MAC})
	}
	authority, err := NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.group.Close() })
	options := configpoc.RuntimeOptionsV2{Pools: pools, GuardDeadlines: true, Routed: authority, RoutedIdentity: identity}
	service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err = service.PrepareRoutedCompositeV1(ctx); err != nil {
		t.Fatal(err)
	}
	if noNetworkBoot {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		if err := authority.group.Close(); err != nil {
			t.Fatal(err)
		}
		// Model a newly supervised namespace on the next boot. Its physical
		// tables are actually absent; the imported schema4 is only a saved witness.
		identity.BootID = "32345678-1234-1234-1234-123456789abc"
		identity.RunID = "2123456789abcdef0123456789abcdef"
		identity.Namespace++
		kernel = &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
		network = &routedTestNetwork{snapshot: snapshot, identity: identity}
		authority, err = NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = authority.group.Close() })
		options.Routed, options.RoutedIdentity, options.BootID = authority, identity, identity.BootID
		service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
		if err != nil {
			t.Fatal("physical Startup4 no-network Boot", err)
		}
		data, present, err := kernel.Observe(ctx, routedactivation.LegacyTable)
		if err != nil || !present {
			t.Fatal("Boot4 missing actual legacy table", err)
		}
		if _, err := firewallnft.VerifyObservation(data, legacy); err != nil || network.calls != 0 || network.active || len(kernel.objects) != 1 {
			t.Fatal("Boot4 did not preserve both imported rules without L3", err)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		if err := authority.group.Close(); err != nil {
			t.Fatal(err)
		}
		authority, err = NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = authority.group.Close() })
		options.Routed = authority
		service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
		if err != nil {
			t.Fatal("confirmed Boot4 fresh helper", err)
		}
	}
	_, token, err := auth.Login("operator", credential)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := auth.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"firewall", "local_services"} {
		if _, e := service.Namespace(binding, domain, time.Hour); !errors.Is(e, configpoc.ErrDenied) {
			t.Fatal("independent legacy writer allowed beside group", domain, e)
		}
	}
	initial, err := service.Status(binding)
	if err != nil {
		t.Fatal(err)
	}
	run := func(request configpoc.OperationRequestV2) configpoc.ResultV2 {
		t.Helper()
		current, e := service.Status(binding)
		if e != nil {
			t.Fatal(e)
		}
		ns, e := service.Namespace(binding, "routed", time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		op, e := service.Admit(binding, ns.ID, current.GlobalGeneration, request)
		if e != nil {
			t.Fatalf("admit %s: %v", request.Kind, e)
		}
		result, e := service.Execute(ctx, binding, op.ID)
		if e != nil {
			t.Fatalf("execute %s: %v", request.Kind, e)
		}
		return result
	}
	if noNetworkBoot {
		edited := legacy.Config
		edited.Rules = append([]configpoc.Rule(nil), legacy.Config.Rules...)
		edited.Rules[0].Action = "deny"
		run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &edited})
		run(configpoc.OperationRequestV2{Kind: configpoc.OpValidate})
		seconds := uint64(30)
		changed := run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
		run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: changed.Operation.ID, Target: changed.Current.RunningRevision})
		if network.calls != 0 || network.active {
			t.Fatal("ordinary schema4 edit configured L3")
		}
	}
	target := configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy}
	run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &target})
	run(configpoc.OperationRequestV2{Kind: configpoc.OpValidate})
	seconds := uint64(30)
	committed := run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	if committed.Current.Confirmation == nil {
		t.Fatal("missing original confirmation")
	}
	observed, err := service.RoutedEffective(ctx, binding)
	if err != nil || !observed.Consistent || observed.Phase != "pending" {
		t.Fatalf("effective: %+v %v", observed, err)
	}
	current, err := service.Current(binding, "")
	if err != nil || current.Routed == nil || current.Routed.Confirmation == nil || current.Routed.Confirmation.Origin != committed.Operation.ID {
		t.Fatalf("confirmation origin not recoverable: %+v %v", current.Routed, err)
	}
	run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.RunningRevision})
	saved := run(configpoc.OperationRequestV2{Kind: configpoc.OpSave})
	if saved.Current.StartupRevision != saved.Current.RunningRevision {
		t.Fatal("save differs from actual confirmed Running")
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing the control plane must leave the helper and confirmed data plane.
	receipt, hash, err := authority.Observe(ctx)
	if err != nil || receipt.Phase != "idle" || hash != committed.Current.RunningRevision {
		t.Fatalf("API close changed dataplane: %+v %s %v", receipt, hash, err)
	}
	if err = authority.group.Close(); err != nil {
		t.Fatal(err)
	}
	foreignIdentity := identity
	foreignIdentity.RunID = "fedcba9876543210fedcba9876543210"
	foreign, e := NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, foreignIdentity)
	if e != nil {
		t.Fatal(e)
	}
	foreignOptions := options
	foreignOptions.Routed = foreign
	foreignOptions.RoutedIdentity = foreignIdentity
	batches, calls := len(kernel.batches), network.calls
	if opened, e := configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, foreignOptions); e == nil {
		_ = opened.Close()
		t.Fatal("foreign helper incarnation adopted durable work")
	}
	if len(kernel.batches) != batches || network.calls != calls {
		t.Fatal("foreign recovery changed physical state")
	}
	_ = foreign.group.Close()
	authority, err = NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.group.Close() })
	options.Routed = authority
	service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
	if err != nil {
		t.Fatal("controller restart", err)
	}
	observed, err = service.RoutedEffective(ctx, binding)
	if err != nil || !observed.Consistent || observed.Running != saved.Current.RunningRevision {
		t.Fatalf("confirmed restart: %+v %v", observed, err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if err = authority.group.Close(); err != nil {
		t.Fatal(err)
	}
	identity.BootID = "22345678-1234-1234-1234-123456789abc"
	identity.RunID = "1123456789abcdef0123456789abcdef"
	kernel = &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
	network = &routedTestNetwork{snapshot: snapshot, identity: identity}
	authority, err = NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.group.Close() })
	options.Routed = &routedBootReplyLostFixture{RoutedAuthority: authority, lose: true}
	options.RoutedIdentity = identity
	options.BootID = identity.BootID
	if first, e := configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options); e == nil {
		_ = first.Close()
		t.Fatal("lost boot apply reply falsely finalized")
	}
	originalBootReceipt, _, e := authority.Observe(ctx)
	if e != nil || originalBootReceipt.Phase != "pending" {
		t.Fatal("boot lease did not remain independently pending", e)
	}
	service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
	if err != nil {
		t.Fatal("Startup6 in fresh namespace with absent tables", err)
	}
	finalBootReceipt, _, e := authority.Observe(ctx)
	if e != nil || !finalBootReceipt.Deadline.Equal(originalBootReceipt.Deadline) {
		t.Fatal("boot restart changed original deadline", e)
	}
	booted, err := service.Status(binding)
	if err != nil || booted.RunningRevision != saved.Current.StartupRevision || booted.GlobalGeneration <= saved.Current.GlobalGeneration || !network.active {
		t.Fatalf("Startup6 boot not verified: %+v %v", booted, err)
	}
	rolled := run(configpoc.OperationRequestV2{Kind: configpoc.OpRollback, Target: initial.StartupRevision, ConfirmSeconds: &seconds})
	if network.active {
		t.Fatal("inverse rollback did not restore original network baseline")
	}
	if _, exists, e := kernel.Observe(ctx, routedactivation.RoutedTable); e != nil || exists {
		t.Fatal("routed table retained", e)
	}
	run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: rolled.Operation.ID, Target: rolled.Current.RunningRevision})
	run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &target})
	run(configpoc.OperationRequestV2{Kind: configpoc.OpValidate})
	last := run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	// The original helper lease survives API close; controller restart resolves
	// the pending transaction by compensating, without inventing a new deadline.
	receipt, hash, err = authority.Observe(ctx)
	if err != nil || receipt.Phase != "pending" || hash != last.Current.RunningRevision {
		t.Fatal("pending helper lease lost", err)
	}
	// An orderly helper stop restores its own pending lease independently. A
	// fresh helper still needs selected recovery authority before becoming idle.
	if err = authority.group.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = NewRoutedAuthority(kernel, network, &routedTestListeners{}, engineOptions, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.group.Close() })
	options.Routed = authority
	service, err = configpoc.OpenRuntimeServiceV2(ctx, areas[2], budget, auth, []configpoc.Engine{engines[0]}, []configpoc.Engine{engines[1]}, options)
	if err != nil {
		t.Fatal("pending controller restart", err)
	}
	status, err := service.Status(binding)
	if err != nil || status.Confirmation != nil || status.RunningRevision != initial.StartupRevision || network.active {
		t.Fatalf("restart failed exact rollback: %+v %v", status, err)
	}
}
