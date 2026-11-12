//go:build linux

package configpoc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

var nativeV2Case = flag.String("andeiva-v2-volume-case", "", "authorized copied config volume case")
var nativeV2ParentMount = flag.String("andeiva-v2-parent-mnt", "", "harness parent mount namespace")
var nativeV2ParentNetwork = flag.String("andeiva-v2-parent-net", "", "harness parent network namespace")
var nativeV2RecoveryReserves = flag.Bool("andeiva-v2-recovery-reserves", false, "qualify prepared recovery reserves on the copied volume")

func nativeV2CaseValid(name string) bool {
	return name == "bytes" || name == "inodes" || name == "open-deleted"
}

func nativeV2NamespacesValid(parentMount, parentNetwork, actualMount, actualNetwork string) bool {
	return regexp.MustCompile(`^mnt:\[[1-9][0-9]*\]$`).MatchString(parentMount) &&
		regexp.MustCompile(`^net:\[[1-9][0-9]*\]$`).MatchString(parentNetwork) &&
		regexp.MustCompile(`^mnt:\[[1-9][0-9]*\]$`).MatchString(actualMount) &&
		regexp.MustCompile(`^net:\[[1-9][0-9]*\]$`).MatchString(actualNetwork) &&
		parentMount != actualMount && parentNetwork != actualNetwork
}

func nativeV2PrivilegesValid(status string) bool {
	required := map[string]string{"Uid": "1000 1000 1000 1000", "Gid": "1000 1000 1000 1000", "Groups": "", "CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000", "CapBnd": "0000000000000000", "CapAmb": "0000000000000000", "NoNewPrivs": "1"}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		want, exists := required[key]
		if !exists {
			continue
		}
		if strings.Join(strings.Fields(value), " ") != want {
			return false
		}
		delete(required, key)
	}
	return len(required) == 0
}

func nativeV2GeometryValid(stat unix.Statfs_t) bool {
	flags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	return stat.Type == unix.EXT4_SUPER_MAGIC && stat.Bsize == 4096 && stat.Frsize == 4096 &&
		stat.Blocks >= 24576 && stat.Blocks <= 32768 && stat.Files == 8192 &&
		int64(stat.Flags)&flags == flags && int64(stat.Flags)&unix.ST_RDONLY == 0
}

// The test never mounts, changes identities, runs subprocesses or selects paths.
// Root's reviewed harness passes only an owned directory through FD3 after drop.
func nativeV2Scope(t *testing.T) *os.Root {
	t.Helper()
	if !nativeV2CaseValid(*nativeV2Case) || os.Geteuid() != 1000 || os.Getegid() != 1000 {
		t.Fatal("invalid native v2 mode or identity")
	}
	// Validate the inherited descriptor before opening anything that could reuse it.
	var stat unix.Stat_t
	if err := unix.Fstat(3, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 || stat.Uid != 1000 || stat.Gid != 1000 {
		t.Fatal("invalid native v2 directory descriptor", err)
	}
	var executable unix.Stat_t
	if err := unix.Fstat(4, &executable); err != nil || executable.Mode&unix.S_IFMT != unix.S_IFREG || executable.Mode&07777 != 0555 || executable.Uid != 0 || executable.Nlink != 1 || executable.Size <= 0 || executable.Size > 32<<20 {
		t.Fatal("invalid pinned native executable", err)
	}
	flags, err := unix.FcntlInt(3, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("native v2 descriptor must be readonly")
	}
	flags, err = unix.FcntlInt(4, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("native executable descriptor must be readonly")
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(3, &fs); err != nil || !nativeV2GeometryValid(fs) {
		t.Fatal("invalid copied config filesystem", err)
	}
	mnt, mountErr := os.Readlink("/proc/self/ns/mnt")
	net, netErr := os.Readlink("/proc/self/ns/net")
	if mountErr != nil || netErr != nil || !nativeV2NamespacesValid(*nativeV2ParentMount, *nativeV2ParentNetwork, mnt, net) {
		t.Fatal("private mount/network namespaces required")
	}
	status, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(status, 65537))
	closeErr := status.Close()
	if readErr != nil || closeErr != nil || len(data) > 65536 || !nativeV2PrivilegesValid(string(data)) {
		t.Fatal("native v2 worker privilege boundary")
	}
	var host unix.Stat_t
	if err = unix.Stat("/", &host); err != nil || host.Dev == stat.Dev {
		t.Fatal("copied filesystem must differ from host root")
	}
	root, err := os.OpenRoot("/proc/self/fd/3")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := dir.Stat()
	entries, readErr := dir.ReadDir(1)
	closeErr = dir.Close()
	if statErr != nil {
		t.Fatal("native descriptor stat", statErr)
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	if statErr != nil || !ok || actual.Dev != stat.Dev || actual.Ino != stat.Ino || len(entries) != 0 || readErr != io.EOF || closeErr != nil {
		t.Fatal("native scope changed or was not empty")
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

// Bootstrap canonical fixture revisions through the real persistence/audit
// primitives, then open the real coordinator. Engines are explicitly simulated.
func nativeV2Coordinator(t *testing.T, scope *os.Root) (*v2Coordinator, *os.Root, []*countedCoordinatorV2Engine, v2TrustedPrincipal, time.Time) {
	t.Helper()
	if err := scope.Mkdir("catalogue", 0700); err != nil {
		t.Fatal(err)
	}
	area, err := scope.OpenRoot("catalogue")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := area.Close(); err != nil {
			t.Error(err)
		}
	})
	subject, err := v2ID("subject", 1)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := v2ID("lineage", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	st := v2State{Format: v2Format, Lineage: lineage, Generation: 1, LiveSlots: 64, Clock: now, Subjects: []v2Subject{{ID: subject, Login: "native-fixture", CredentialRevision: checkpointDigest([]byte("test fixture revision"))}}, Namespaces: []v2Namespace{}}
	budget := v2Budget{Bytes: 64 << 20, Inodes: 4096}
	if *nativeV2RecoveryReserves {
		// Explicit test profile; the finite filesystem remains the physical limit.
		budget = v2Budget{Bytes: 1 << 30, Inodes: 32768}
	}
	s, err := createV2(area, budget, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s.lock != nil {
			_ = s.close()
		}
	})
	fw, err := Canonical(Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	ls, err := Canonical(localSample(t, 9443))
	if err != nil {
		t.Fatal(err)
	}
	domain := func(r Revision) v2DomainSnapshot {
		return v2DomainSnapshot{Generation: 1, Running: r, Startup: r, LastGood: r}
	}
	state := v2Configuration{Firewall: domain(fw), LocalServices: domain(ls)}
	if err = state.refresh(); err != nil {
		t.Fatal(err)
	}
	engines := []*countedCoordinatorV2Engine{{base: NewSimEngine("native-v2-firewall")}, {base: NewSimEngine("native-v2-local")}}
	engines[0].base.Drift(fw.Hash)
	engines[1].base.Drift(ls.Hash)
	c := &v2Coordinator{store: s, firewall: []Engine{engines[0]}, local: []Engine{engines[1]}, options: v2CoordinatorOptions{Now: func() time.Time { return now }, ManualTimeout: true}}
	if err = c.persistRevisions(state); err != nil {
		t.Fatal(err)
	}
	issued, err := v2ID("initialize", 1)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := c.appendAuditLocked(&state, issued, "", "", "system", "initialize", "verified", s.state.Generation, now)
	if err != nil {
		t.Fatal(err)
	}
	state.VerifiedIndex, err = c.verifiedInsert("", 0, v2VerifiedEntry{Revision: state.Running.Hash, Audit: audit, Operation: issued})
	if err != nil {
		t.Fatal(err)
	}
	next := clone(s.state)
	next.Configuration = &state
	if err = s.publish(next); err != nil {
		t.Fatal(err)
	}
	c, err = openCoordinatorV2(context.Background(), s, []Engine{engines[0]}, []Engine{engines[1]}, c.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	if *nativeV2RecoveryReserves {
		nativeV2AttachRecoveryReserves(t, c, scope)
	}
	return c, area, engines, v2TrustedPrincipal{Subject: subject, Role: RoleAdmin}, now
}

func nativeV2AttachRecoveryReserves(t *testing.T, c *v2Coordinator, scope *os.Root) {
	t.Helper()
	var pools []*recoveryreserve.PoolV2
	for _, spec := range []struct {
		name     string
		role     recoveryreserve.RoleV2
		capacity int
	}{{"admission", recoveryreserve.AdmissionV2, 4096}, {"plan", recoveryreserve.PlanV2, 16384}, {"emergency", recoveryreserve.EmergencyV2, 8192}} {
		if err := scope.Mkdir(spec.name, 0700); err != nil {
			t.Fatal(err)
		}
		area, err := scope.OpenRoot(spec.name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = area.Close() })
		pool, err := recoveryreserve.PrepareV2(area, 18, spec.capacity, spec.role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pool.Close() })
		pools = append(pools, pool)
	}
	manager, err := newReserveManagerV2(pools[0], pools[1], pools[2])
	if err != nil {
		t.Fatal(err)
	}
	if err = c.store.enableClosingCreditsLocked(); err != nil {
		t.Fatal(err)
	}
	c.store.reserves, c.options.Reserves = manager, manager
}

func nativeV2Stat(t *testing.T, scope *os.Root) unix.Statfs_t {
	t.Helper()
	f, err := scope.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	var result unix.Statfs_t
	syncErr := unix.Syncfs(int(f.Fd()))
	statErr, closeErr := unix.Fstatfs(int(f.Fd()), &result), f.Close()
	if syncErr != nil || statErr != nil || closeErr != nil {
		t.Fatal(syncErr, statErr, closeErr)
	}
	return result
}

func TestNativeV2VolumePressure(t *testing.T) {
	if *nativeV2Case == "" {
		t.Skip("explicit authorized copied-volume harness only")
	}
	scope := nativeV2Scope(t)
	c, area, engines, p, now := nativeV2Coordinator(t, scope)
	s := c.store
	config := coordinatorV2Rule("native-pressure-baseline")
	if _, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
		t.Fatal(err)
	}
	immediate := uint64(0)
	_, committed, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &immediate})
	if err != nil {
		t.Fatal(err)
	}
	retained := committed.Operation
	if *nativeV2RecoveryReserves {
		coordinatorV2Stage(t, c, p, "native-confirmation-capacity")
		ns, err := s.namespace(p.Subject, "firewall", now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.reserveBeforeAdmissionV2(); err != nil {
			t.Fatal(err)
		}
		before := clone(s.state)
		selected, used := s.selector, s.used
		seconds := uint64(30)
		for _, engine := range engines {
			engine.reset()
		}
		_, err = s.admit(p.Subject, ns.ID, before.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, now)
		if !errors.Is(err, errV2Limited) || !reserveJSONEqualV2(before, s.state) || selected != s.selector || used != s.used || s.blocked {
			t.Fatalf("finite closing refusal: error=%v state_equal=%t selector_equal=%t used_equal=%t blocked=%t used_before=%+v used_after=%+v", err, reserveJSONEqualV2(before, s.state), selected == s.selector, used == s.used, s.blocked, used, s.used)
		}
		for _, engine := range engines {
			if engine.applies.Load() != 0 || engine.reads.Load() != 0 || engine.validations.Load() != 0 {
				t.Fatal("confirmation capacity refusal touched an engine")
			}
		}
	}
	ns, err := s.namespace(p.Subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.reserveBeforeAdmissionV2(); err != nil {
		t.Fatal(err)
	}
	before, selected, used := clone(s.state), s.selector, s.used
	initial := nativeV2Stat(t, scope)
	for _, e := range engines {
		e.reset()
	}
	var held *os.File
	var fillers []string
	cleanup := func() {
		if held != nil {
			if err := held.Close(); err != nil {
				t.Error(err)
			}
			held = nil
		}
		for _, name := range fillers {
			if err := scope.Remove(name); err != nil {
				t.Error(err)
			}
		}
		fillers = nil
		_ = nativeV2Stat(t, scope)
	}
	defer cleanup()
	if *nativeV2Case == "inodes" {
		exhausted := false
		for i := 0; i <= 8192; i++ {
			name := fmt.Sprintf("filler-%04d", i)
			f, err := scope.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
			if err != nil {
				if !errors.Is(err, unix.ENOSPC) {
					t.Fatal(err)
				}
				exhausted = true
				break
			}
			fillers = append(fillers, name)
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !exhausted {
			t.Fatal("actual inode ENOSPC not reached")
		}
	} else {
		held, err = scope.OpenFile("filler-bytes", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		fillers = append(fillers, "filler-bytes")
		block := make([]byte, 1<<20)
		exhausted := false
		for i := 0; i < 129; i++ {
			_, err = held.Write(block)
			if err != nil {
				if !errors.Is(err, unix.ENOSPC) {
					t.Fatal(err)
				}
				exhausted = true
				break
			}
		}
		if !exhausted {
			t.Fatal("actual byte ENOSPC not reached")
		}
		if err = held.Sync(); err != nil && !errors.Is(err, unix.ENOSPC) {
			t.Fatal(err)
		}
		if *nativeV2Case == "open-deleted" {
			if err = scope.Remove("filler-bytes"); err != nil {
				t.Fatal(err)
			}
			fillers = nil
			if _, err = scope.Lstat("filler-bytes"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("deleted file still named", err)
			}
		}
	}
	pressured := nativeV2Stat(t, scope)
	if *nativeV2Case == "inodes" {
		if pressured.Ffree != 0 || pressured.Bavail*4096 <= 32<<20 {
			t.Fatal("inode exhaustion not distinguished from bytes")
		}
	} else if pressured.Bavail >= initial.Bavail {
		t.Fatal("allocated pressure not observed")
	}
	if _, err = s.admit(p.Subject, ns.ID, before.Generation, v2Request{Kind: OpSave}, now); !errors.Is(err, errV2Limited) {
		t.Fatal("pressure admission", err)
	}
	if !reserveJSONEqualV2(before, s.state) || selected != s.selector || used != s.used || s.blocked {
		t.Fatal("pressure changed selected state/reservations")
	}
	for _, e := range engines {
		if e.applies.Load() != 0 || e.validations.Load() != 0 || e.reads.Load() != 0 {
			t.Fatal("rejected admission called an engine")
		}
	}
	current, generation, err := c.status(p)
	if err != nil || generation != before.Generation || !reflect.DeepEqual(current, *before.Configuration) {
		t.Fatal("verified current under pressure", err)
	}
	got, err := s.lookup(p.Subject, retained.ID)
	if err != nil || !reflect.DeepEqual(got, retained) {
		t.Fatal("retained lookup under pressure", err)
	}
	replayed, err := c.execute(context.Background(), p, retained.ID)
	if err != nil || !reflect.DeepEqual(replayed.Operation, retained) || !reflect.DeepEqual(replayed.Current, *before.Configuration) {
		t.Fatal("terminal replay under pressure", err)
	}
	if err = s.readSelection(); err != nil || !reflect.DeepEqual(before, s.state) {
		t.Fatal("selected bytes verification under pressure", err)
	}
	for _, e := range engines {
		if e.applies.Load() != 0 {
			t.Fatal("terminal replay reapplied an engine")
		}
	}
	cleanup()
	released := nativeV2Stat(t, scope)
	if (*nativeV2Case == "inodes" && released.Ffree <= pressured.Ffree) || (*nativeV2Case != "inodes" && released.Bavail <= pressured.Bavail) {
		t.Fatal("pressure cleanup did not release allocation")
	}
	if _, _, err = coordinatorV2Request(t, c, p, v2Request{Kind: OpSave}); err != nil {
		t.Fatal("post-pressure execution", err)
	}
	final := clone(s.state)
	c.close()
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	s.lock = nil // The test fixture cleanup owns only the still-open handle.
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal("cold reopen", err)
	}
	defer reopened.close()
	if !reflect.DeepEqual(reopened.state, final) {
		t.Fatal("reopened state changed")
	}
	checkV2Physical(t, reopened)
	t.Logf("case=%s logical=%d files_allocated=%d directory_allocated=%d owned_inodes=%d available_before=%d available_pressure=%d available_after=%d free_inodes_pressure=%d; SIM engines", *nativeV2Case, reopened.used.Bytes, reopened.physical.files, reopened.physical.directory, reopened.physical.inodes, initial.Bavail*4096, pressured.Bavail*4096, released.Bavail*4096, pressured.Ffree)
	fmt.Printf("ANDEIVA_NATIVE_V2_CASE_PASS=%s\n", *nativeV2Case)
	if *nativeV2RecoveryReserves {
		fmt.Printf("ANDEIVA_NATIVE_R2_CASE_PASS=%s\n", *nativeV2Case)
	}
}

func TestNativeV2PressureGuards(t *testing.T) {
	for _, name := range []string{"", "readonly", "../bytes", "bytes\n", "BYTES"} {
		if nativeV2CaseValid(name) {
			t.Fatal("invalid case admitted", name)
		}
	}
	for _, name := range []string{"bytes", "inodes", "open-deleted"} {
		if !nativeV2CaseValid(name) {
			t.Fatal(name)
		}
	}
	if !nativeV2NamespacesValid("mnt:[1]", "net:[2]", "mnt:[3]", "net:[4]") {
		t.Fatal("valid isolated namespaces refused")
	}
	for _, args := range [][4]string{{"mnt:[1]", "net:[2]", "mnt:[1]", "net:[4]"}, {"mnt:[1]", "net:[2]", "mnt:[3]", "net:[2]"}, {"", "net:[2]", "mnt:[3]", "net:[4]"}, {"mnt:[1]x", "net:[2]", "mnt:[3]", "net:[4]"}} {
		if nativeV2NamespacesValid(args[0], args[1], args[2], args[3]) {
			t.Fatal("namespace guard accepted", args)
		}
	}
	status := "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if !nativeV2PrivilegesValid(status) {
		t.Fatal("valid restricted worker refused")
	}
	for _, pair := range [][2]string{{"1000 1000 1000 1000", "0 0 0 0"}, {"Groups:\n", "Groups: 27\n"}, {"CapEff:\t0000000000000000", "CapEff:\t0000000000000001"}, {"NoNewPrivs:\t1", "NoNewPrivs:\t0"}} {
		if nativeV2PrivilegesValid(strings.Replace(status, pair[0], pair[1], 1)) {
			t.Fatal("privilege guard accepted", pair[0])
		}
	}
	fs := unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Bsize: 4096, Frsize: 4096, Blocks: 32768, Files: 8192, Flags: unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC}
	if !nativeV2GeometryValid(fs) {
		t.Fatal("valid geometry refused")
	}
	for _, change := range []func(*unix.Statfs_t){func(s *unix.Statfs_t) { s.Blocks++ }, func(s *unix.Statfs_t) { s.Files++ }, func(s *unix.Statfs_t) { s.Flags |= unix.ST_RDONLY }, func(s *unix.Statfs_t) { s.Flags = 0 }, func(s *unix.Statfs_t) { s.Type = unix.TMPFS_MAGIC }} {
		invalid := fs
		change(&invalid)
		if nativeV2GeometryValid(invalid) {
			t.Fatal("unsafe filesystem accepted")
		}
	}
}

func TestNativeV2PressureBootstrapUsesRealCoordinator(t *testing.T) {
	scope, _ := checkpointFixtureArea(t)
	c, area, engines, p, _ := nativeV2Coordinator(t, scope)
	config := coordinatorV2Rule("native-bootstrap-unit")
	if _, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
		t.Fatal(err)
	}
	immediate := uint64(0)
	_, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &immediate})
	if err != nil || result.Operation.Outcome == nil || result.Operation.Outcome.Code != "applied" || result.Current.Firewall.Running.Hash != engines[0].base.Current() {
		t.Fatal("native fixture did not use the verified coordinator", err)
	}
	before := clone(c.store.state)
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	c.store.lock = nil
	reopened, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if !reflect.DeepEqual(before, reopened.state) {
		t.Fatal("native fixture changed on reopen")
	}
}

func TestNativeV2ReserveClosingRefusalPreservesCanonicalState(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "finite-space-refusal")
	s := c.store
	ns, err := s.namespace(p.Subject, "firewall", *now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.reserveBeforeAdmissionV2(); err != nil {
		t.Fatal(err)
	}
	s.spaceProbe = func(*os.File) (storageSpace, error) {
		return storageSpace{AvailableBytes: 128 << 20, AvailableInodes: 8192, BlockSize: 4096}, nil
	}
	before := clone(s.state)
	selected, used := s.selector, s.used
	// Empty optional reserve slices round-trip as nil. Compare the canonical
	// state bytes, together with the exact selector and allocation counters.
	seconds := uint64(30)
	_, err = s.admit(p.Subject, ns.ID, before.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, *now)
	if !errors.Is(err, errV2Limited) || !reserveJSONEqualV2(before, s.state) || selected != s.selector || used != s.used || s.blocked {
		t.Fatalf("physical refusal changed canonical state: error=%v state=%t selector=%t used=%t blocked=%t", err, reserveJSONEqualV2(before, s.state), selected == s.selector, used == s.used, s.blocked)
	}
}
