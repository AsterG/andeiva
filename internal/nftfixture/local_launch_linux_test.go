package nftfixture

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func handoffPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

func handoffStream(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "stream-a"), os.NewFile(uintptr(pair[1]), "stream-b")
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func handoffFixture(t *testing.T) *Fixture {
	t.Helper()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	id, err := networkNamespaceInode(int(ns.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return &Fixture{self: "/trusted/andeiva-local-lab", uid: 1001, gid: 1001, host: id + 1, localOnly: true, namespaces: map[string]*namespace{
		"gateway": {handle: ns, inode: id}, "source": {handle: ns, inode: id}, "sink": {handle: ns, inode: id},
	}}
}

func TestLocalHandoffRejectsWrongTypesAndAliases(t *testing.T) {
	r, w := handoffPipe(t)
	a, b := handoffStream(t)
	if !validLocalDescriptor(int(r.Fd()), localBootstrap) || validLocalDescriptor(int(w.Fd()), localBootstrap) {
		t.Fatal("bootstrap direction")
	}
	if !validLocalDescriptor(int(a.Fd()), localStream) || !validLocalDescriptor(int(b.Fd()), localStream) {
		t.Fatal("socketpair rejected")
	}
	if validLocalDescriptor(int(a.Fd()), localBootstrap) || validLocalDescriptor(int(r.Fd()), localStream) || validLocalDescriptor(int(a.Fd()), localLAN) {
		t.Fatal("cross-role descriptor accepted")
	}
	regular, err := os.CreateTemp(t.TempDir(), "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if validLocalDescriptor(int(regular.Fd()), localBootstrap) {
		t.Fatal("path-backed bootstrap accepted")
	}
	duplicate, err := syscall.Dup(int(a.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	copy := os.NewFile(uintptr(duplicate), "duplicate")
	defer copy.Close()
	if validateLocalFiles([]*os.File{a, copy}, []localDescriptorKind{localStream, localStream}) == nil {
		t.Fatal("aliased control channels")
	}
	if validateLocalFiles([]*os.File{a, b, r}, []localDescriptorKind{localStream, localStream, localBootstrap}) != nil {
		t.Fatal("distinct descriptors rejected")
	}
	if validateLocalFiles([]*os.File{nil}, []localDescriptorKind{localBootstrap}) == nil || validateLocalFiles(nil, probeDescriptorKinds) == nil {
		t.Fatal("missing descriptor accepted")
	}
	unconnected, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(unconnected)
	if validLocalDescriptor(unconnected, localStream) {
		t.Fatal("unconnected control accepted")
	}
	datagram, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(datagram[0])
	defer syscall.Close(datagram[1])
	if validLocalDescriptor(datagram[0], localStream) {
		t.Fatal("datagram control accepted")
	}
}

func TestLocalRecoveryDescriptorsRequireSpecificListeners(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !validLocalDescriptor(int(file.Fd()), localLoopback) || validLocalDescriptor(int(file.Fd()), localLAN) || validLocalDescriptor(int(file.Fd()), localStream) {
		t.Fatal("recovery role mismatch")
	}
	for _, test := range []struct {
		address         string
		loopback, valid bool
	}{
		{"192.0.2.1:18443", false, true}, {"127.0.0.1:18443", true, true},
		{"[2001:db8::1]:18443", false, true}, {"[::1]:18443", true, true},
		{"0.0.0.0:18443", false, false}, {"[::]:18443", false, false},
		{"192.0.2.1:443", false, false}, {"127.0.0.1:18443", false, false},
		{"192.0.2.1:18443", true, false}, {"224.0.0.1:18443", false, false},
		{"[::ffff:192.0.2.1]:18443", false, false}, {"[fe80::1]:18443", false, false},
		{"[fe80::1%eth0]:18443", false, false},
	} {
		if validRecoveryAddress(netip.MustParseAddrPort(test.address), test.loopback) != test.valid {
			t.Fatal(test)
		}
	}
}

func TestLocalHelperLaunchPinsFixedDescriptorsAndDistinctIdentity(t *testing.T) {
	f := handoffFixture(t)
	tx, _ := handoffStream(t)
	worker, _ := handoffStream(t)
	collector, _ := handoffStream(t)
	bootstrap, _ := handoffPipe(t)
	files := []*os.File{tx, worker, collector, bootstrap}
	run := strings.Repeat("a", 32)
	cmd, err := f.localLaunchCommand(context.Background(), "helper", run, "", 1002, 1002, files)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != enterPath || !slices.Equal(cmd.Args[1:3], []string{"--net=/proc/self/fd/3", "--"}) || len(cmd.ExtraFiles) != 5 || cmd.ExtraFiles[0] != f.namespaces["gateway"].handle || !slices.Equal(cmd.ExtraFiles[1:], files) || !slices.Equal(cmd.Env, fixedEnvironment()) {
		t.Fatal("untrusted launch plan", cmd.Args)
	}
	joined := strings.Join(cmd.Args, " ")
	if strings.Count(joined, "-all,+net_admin") != 3 || !strings.Contains(joined, "--reuid=1002 --regid=1002 --clear-groups") || strings.Contains(joined, "sys_admin") || !strings.HasSuffix(joined, f.self+" --guardian "+run+" "+strconv.FormatUint(f.host, 10)+" "+strconv.Itoa(os.Getpid())) {
		t.Fatal("helper capability/role escalation", cmd.Args)
	}
	if cmd.Process != nil || cmd.Stdin != nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("unit test launched process or inherited input")
	}
	for _, identity := range [][2]uint32{{0, 1002}, {1002, 0}, {1001, 1002}, {1002, 1001}, {^uint32(0), 1002}} {
		if _, err := f.localLaunchCommand(context.Background(), "helper", run, "", identity[0], identity[1], files); err == nil {
			t.Fatal("unsafe identity", identity)
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 32), run + ";sh", "../run"} {
		if _, err := f.localLaunchCommand(context.Background(), "helper", bad, "", 1002, 1002, files); err == nil {
			t.Fatal("unbound run accepted")
		}
	}
	if _, err := f.localLaunchCommand(context.Background(), "helper", run, "source", 1002, 1002, files); err == nil {
		t.Fatal("helper in client namespace")
	}
	f.localOnly = false
	if _, err := f.localLaunchCommand(context.Background(), "helper", run, "", 1002, 1002, files); err == nil {
		t.Fatal("local launch in forwarding fixture")
	}
}

func TestLocalProbeLaunchCannotSelectHostOrPrivileges(t *testing.T) {
	f := handoffFixture(t)
	bootstrap, _ := handoffPipe(t)
	for _, side := range []string{"source", "sink"} {
		cmd, err := f.localLaunchCommand(context.Background(), "probe", "", side, f.uid, f.gid, []*os.File{bootstrap})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(cmd.Args, " ")
		if strings.Contains(joined, "+net_admin") || len(cmd.ExtraFiles) != 2 || cmd.ExtraFiles[0] != f.namespaces[side].handle || cmd.ExtraFiles[1] != bootstrap || !strings.HasSuffix(joined, "--local-probe "+strconv.FormatUint(f.host, 10)+" "+strconv.Itoa(os.Getpid())+" "+side) {
			t.Fatal("probe expansion", cmd.Args)
		}
	}
	for _, side := range []string{"", "gateway", "host", "source;sh", "../sink"} {
		if _, err := f.localLaunchCommand(context.Background(), "probe", "", side, f.uid, f.gid, []*os.File{bootstrap}); err == nil {
			t.Fatal("arbitrary probe role accepted")
		}
	}
	for _, role := range []string{"shell", "keeper", "../api"} {
		if _, err := f.localLaunchCommand(context.Background(), role, "", "", f.uid, f.gid, []*os.File{bootstrap}); err == nil {
			t.Fatal("arbitrary executable role")
		}
	}
}

func TestLocalProcessStatusRequiresExactPrivilegeEnvelope(t *testing.T) {
	status := func(caps string) string {
		return fmt.Sprintf("Uid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\nCapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\nCapBnd:\t%s\nCapAmb:\t%s\nNoNewPrivs:\t1\n", caps, caps, caps, caps, caps)
	}
	plain, helper := status("0000000000000000"), status("0000000000001000")
	if !validLocalProcessStatus([]byte(plain), 1001, 1002, false) || !validLocalProcessStatus([]byte(helper), 1001, 1002, true) || validLocalProcessStatus([]byte(helper), 1001, 1002, false) || validLocalProcessStatus([]byte(plain), 1001, 1002, true) {
		t.Fatal("capability role distinction")
	}
	for _, bad := range []string{
		strings.Replace(plain, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		strings.Replace(plain, "Groups:\n", "Groups:\t1002\n", 1),
		strings.Replace(plain, "Uid:\t1001", "Uid:\t0", 1),
		strings.Replace(plain, "CapAmb:\t0000000000000000", "CapAmb:\t0000000000200000", 1),
		strings.Replace(plain, "CapBnd:\t0000000000000000\n", "", 1),
		plain + "NoNewPrivs:\t1\n",
	} {
		if validLocalProcessStatus([]byte(bad), 1001, 1002, false) {
			t.Fatal("bad privileges accepted")
		}
	}
}

func TestLocalParentRequiresAllRootIdentities(t *testing.T) {
	if !rootLocalParent([]byte("Name:\tsupervisor\nUid:\t0\t0\t0\t0\n")) {
		t.Fatal("root parent rejected")
	}
	for _, bad := range []string{"", "Uid:\t0\t1001\t0\t0\n", "Uid:\t1001\t0\t0\t0\n", "Uid:\t0\t0\t0\t1001\n", "Uid:\t0\t0\t0\n", "Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n"} {
		if rootLocalParent([]byte(bad)) {
			t.Fatal("non-root or ambiguous parent accepted")
		}
	}
}

func TestLocalGuardRejectsMissingAndSubstitutedInheritedDescriptors(t *testing.T) {
	if os.Getenv("ANDEIVA_TEST_LOCAL_GUARD") == "1" {
		for _, guard := range []func(uint64, int, uint32, uint32) error{GuardLocalAPI, GuardLocalHelper, GuardLocalProbe} {
			if guard(1, os.Getppid(), uint32(os.Getuid()), uint32(os.Getgid())) == nil {
				os.Exit(3)
			}
		}
		return
	}
	for _, path := range []string{"", "/dev/null", "/proc/self/ns/net"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLocalGuardRejectsMissingAndSubstitutedInheritedDescriptors$")
		cmd.Env = append(os.Environ(), "ANDEIVA_TEST_LOCAL_GUARD=1")
		if path != "" {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			cmd.ExtraFiles = []*os.File{file}
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("guard case %q: %v %s", path, err, out)
		}
	}
}
