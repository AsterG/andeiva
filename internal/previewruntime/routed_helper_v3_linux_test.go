//go:build linux

package previewruntime

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

type helperIdentityFixtureV3 struct {
	configpoc.RoutedAuthorityV1
	identity networkexecutor.OwnedNamespaceIdentity
}

func (a *helperIdentityFixtureV3) Identity() networkexecutor.OwnedNamespaceIdentity {
	return a.identity
}
func helperFixtureV3(t *testing.T) (Metadata, Identities, RoutedHelperOptionsV3) {
	t.Helper()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	ids := Identities{SchemaVersion: 1, APIUID: uid, APIGID: gid + 3, HelperUID: uid + 1, IPCGID: gid + 2}
	m := Metadata{SchemaVersion: 1, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 11, GatewayNamespace: 22, SourceNamespace: 33, SinkNamespace: 44}
	create := func() (*os.Root, recoveryreserve.ReaderAccessV2) {
		r := routedCoordinatorRoot(t)
		if e := os.Chmod(r.Name(), os.ModeSetgid|0750); e != nil {
			t.Fatal(e)
		}
		info, e := r.Stat(".")
		if e != nil {
			t.Fatal(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		return r, recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: uid, ReaderGID: gid, Device: st.Dev, Inode: st.Ino}
	}
	store, access := create()
	makePool := func(role recoveryreserve.RoleV2, capacity int) RoutedReaderRootV3 {
		r, a := create()
		p, e := recoveryreserve.PrepareSharedV2(r, 18, capacity, role, a)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = p.Close() })
		profile, e := p.Profile()
		if e != nil {
			t.Fatal(e)
		}
		return RoutedReaderRootV3{Root: r, Access: a, Profile: profile}
	}
	o := RoutedHelperOptionsV3{Store: store, Access: access, Admission: makePool(recoveryreserve.AdmissionV2, 4096), Plan: makePool(recoveryreserve.PlanV2, 16384), Emergency: makePool(recoveryreserve.EmergencyV2, 8192), Budget: configpoc.SelectionReadBudgetV2{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128}}
	o.Authority = &helperIdentityFixtureV3{identity: networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: 22, Host: 11, BootID: m.BootID, RunID: m.RunID}}
	return m, ids, o
}
func TestRoutedHelperV3RejectsReadinessSubstitutions(t *testing.T) {
	m, ids, o := helperFixtureV3(t)
	if e := routedHelperReadinessV3(m, ids, o); e != nil {
		t.Fatal("valid pinned readiness", e)
	}
	for _, change := range []func(*Metadata, *Identities, *RoutedHelperOptionsV3){
		func(m *Metadata, _ *Identities, _ *RoutedHelperOptionsV3) { m.GatewayNamespace = m.HostNamespace },
		func(_ *Metadata, i *Identities, _ *RoutedHelperOptionsV3) { i.HelperUID++ },
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) { o.Plan.Profile.Capacity++ },
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) {
			o.Plan.Profile.Role = recoveryreserve.AdmissionV2
		},
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) { o.Plan.Profile.ID = o.Admission.Profile.ID },
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) {
			o.Plan.Root = o.Admission.Root
			o.Plan.Access = o.Admission.Access
		},
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) { o.Access.OwnerUID++ },
		func(_ *Metadata, i *Identities, o *RoutedHelperOptionsV3) { i.APIGID = o.Access.ReaderGID },
		func(_ *Metadata, _ *Identities, o *RoutedHelperOptionsV3) { o.Emergency.Access.ReaderGID++ },
	} {
		a, b, c := m, ids, o
		change(&a, &b, &c)
		if routedHelperReadinessV3(a, b, c) == nil {
			t.Fatal("substitution accepted")
		}
	}
	if _, e := OpenRoutedHelperV3(context.Background(), m, ids, o); e == nil {
		t.Fatal("fixture identity substituted for real helper process")
	}
}
func TestRoutedHelperV3ProcessAllowlist(t *testing.T) {
	ids := Identities{SchemaVersion: 1, APIUID: 1001, APIGID: 1002, HelperUID: 1003, IPCGID: 1004}
	status := "CapInh:\t0000000000001000\nCapPrm:\t0000000000001000\nCapEff:\t0000000000001000\nCapBnd:\t0000000000001000\nCapAmb:\t0000000000001000\nNoNewPrivs:\t1\n"
	if routedHelperProcessFieldsV3(1003, 1003, 1004, 1004, []int{1004, 1005}, status, ids, 1005) != nil {
		t.Fatal("exact reader group profile denied")
	}
	for _, groups := range [][]int{{1004}, {1004, 1005, 1006}, {0, 1005}, {-1, 1005}} {
		if routedHelperProcessFieldsV3(1003, 1003, 1004, 1004, groups, status, ids, 1005) == nil {
			t.Fatal("foreign groups admitted", groups)
		}
	}
	for _, bad := range []string{strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(status, "CapEff:\t0000000000001000", "CapEff:\t0000000000001001", 1), status + "CapEff:\t0000000000001000\n"} {
		if routedHelperProcessFieldsV3(1003, 1003, 1004, 1004, []int{1005}, bad, ids, 1005) == nil {
			t.Fatal("capability profile admitted")
		}
	}
	if routedHelperProcessFieldsV3(1001, 1001, 1004, 1004, []int{1005}, status, ids, 1005) == nil {
		t.Fatal("writer UID admitted as helper")
	}
}
func helperFDsV3(t *testing.T) map[string]bool {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]bool{}
	for _, entry := range entries {
		out[entry.Name()] = true
	}
	return out
}
func TestRoutedHelperV3OpensOnlyReadOnlyPoolDescriptors(t *testing.T) {
	m, ids, o := helperFixtureV3(t)
	before := helperFDsV3(t)
	runtime, e := assembleRoutedHelperV3(context.Background(), m, ids, o)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	after := helperFDsV3(t)
	count := 0
	for fd := range after {
		if before[fd] {
			continue
		}
		path, e := os.Readlink("/proc/self/fd/" + fd)
		if e != nil {
			continue
		}
		own := false
		for _, root := range []RoutedReaderRootV3{o.Admission, o.Plan, o.Emergency} {
			own = own || strings.HasPrefix(path, root.Root.Name()+"/")
		}
		if !own {
			continue
		}
		number, e := strconv.Atoi(fd)
		if e != nil {
			t.Fatal(e)
		}
		flags, e := unix.FcntlInt(uintptr(number), unix.F_GETFL, 0)
		if e != nil {
			t.Fatal(e)
		}
		if flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("helper opened writable descriptor", fd, path, flags)
		}
		count++
	}
	if count < 3 {
		t.Fatal("vacuous descriptor check", count)
	}
	if e = runtime.Close(); e != nil {
		t.Fatal(e)
	}
	for _, resource := range []RoutedReaderRootV3{o.Admission, o.Plan, o.Emergency} {
		if e = resource.Access.CheckDirectory(resource.Root); e != nil {
			t.Fatal("borrowed root closed", e)
		}
	}
	if runtime.closed != true {
		t.Fatal("runtime did not close")
	}
}

type helperGuardianFixtureV3 struct {
	helperIdentityFixtureV3
	guardian *nftguardian.Guardian
	engine   *configpoc.SimEngine
}

func (a *helperGuardianFixtureV3) Observe(context.Context) (configpoc.RoutedReceiptV1, string, error) {
	state := a.guardian.Status()
	return configpoc.RoutedReceiptV1{Phase: state.Phase, ID: state.ID, Previous: state.Previous, Target: state.Target, Deadline: state.Deadline}, a.engine.Current(), nil
}
func TestRoutedHelperV3DisconnectAndReaderCloseKeepGuardian(t *testing.T) {
	m, ids, o := helperFixtureV3(t)
	_, guardian, engine, previous, target := fixtureSessionV2(t)
	ctx := context.Background()
	if e := guardian.Bootstrap(ctx, previous); e != nil {
		t.Fatal(e)
	}
	authority := &helperGuardianFixtureV3{helperIdentityFixtureV3: helperIdentityFixtureV3{identity: o.Authority.Identity()}, guardian: guardian, engine: engine}
	o.Authority = authority
	runtime, e := assembleRoutedHelperV3(ctx, m, ids, o)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	deadline := time.Now().UTC().Add(800 * time.Millisecond)
	if e = guardian.ArmUntil("helper-reader-lifetime", previous, target, deadline); e != nil {
		t.Fatal(e)
	}
	receipt := guardian.Status()
	if e = guardian.ApplyLease(ctx, target, receipt); e != nil {
		t.Fatal(e)
	}
	channel, done, e := routedTransportConnectV3(t, ctx, runtime.session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = channel.Call(ctx, "observe", struct{}{}); e != nil {
		t.Fatal(e)
	}
	_ = channel.Close()
	<-done
	if engine.Current() != target.Hash || guardian.Status().Deadline != receipt.Deadline {
		t.Fatal("disconnect changed policy or guardian deadline")
	}
	if e = runtime.Close(); e != nil {
		t.Fatal(e)
	}
	if engine.Current() != target.Hash {
		t.Fatal("reader shutdown changed effective policy")
	}
	limit := time.Now().Add(2 * time.Second)
	for engine.Current() != previous.Hash && time.Now().Before(limit) {
		time.Sleep(10 * time.Millisecond)
	}
	if engine.Current() != previous.Hash || guardian.Status().Phase != "expired" {
		t.Fatal("independent guardian did not expire")
	}
}

func TestRoutedHelperV3FailedOpenClosesOnlyOwnedReaders(t *testing.T) {
	m, ids, original := helperFixtureV3(t)
	for _, badBudget := range []bool{false, true} {
		o := original
		if badBudget {
			o.Budget = configpoc.SelectionReadBudgetV2{}
		} else {
			o.Plan.Profile.ID = strings.Repeat("a", 32)
		}
		before := helperFDsV3(t)
		if runtime, e := assembleRoutedHelperV3(context.Background(), m, ids, o); e == nil || runtime != nil {
			t.Fatal("invalid reader accepted")
		}
		for fd := range helperFDsV3(t) {
			if before[fd] {
				continue
			}
			path, e := os.Readlink("/proc/self/fd/" + fd)
			if e != nil {
				continue
			}
			for _, resource := range []RoutedReaderRootV3{o.Admission, o.Plan, o.Emergency} {
				if strings.HasPrefix(path, resource.Root.Name()+"/") {
					t.Fatal("failed assembly leaked reader", fd, path)
				}
			}
		}
		for _, resource := range []RoutedReaderRootV3{o.Admission, o.Plan, o.Emergency} {
			if resource.Access.CheckDirectory(resource.Root) != nil {
				t.Fatal("borrowed root closed")
			}
		}
	}
}
