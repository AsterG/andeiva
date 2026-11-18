//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

func serverRawFixtureV2() (routedDHCPServerBootstrapV2, [14]routedDHCPServerRawFDV2) {
	b := serverBootstrapFixtureV2()
	var raw [14]routedDHCPServerRawFDV2
	for i, item := range []struct {
		kind int
		id   uint64
	}{{unix.CLONE_NEWNET, 20}, {unix.CLONE_NEWNET, 10}, {unix.CLONE_NEWNS, 30}} {
		raw[i+3] = routedDHCPServerRawFDV2{stat: unix.Stat_t{Ino: item.id}, fs: unix.Statfs_t{Type: unix.NSFS_MAGIC}, namespace: item.kind}
	}
	raw[6] = routedDHCPServerRawFDV2{stat: unix.Stat_t{Dev: 7, Ino: 61, Mode: unix.S_IFREG | 0440, Gid: 62021, Nlink: 1, Size: 128}}
	raw[7] = routedDHCPServerRawFDV2{stat: unix.Stat_t{Dev: 7, Ino: 71, Mode: unix.S_IFDIR | 0700, Uid: 62020, Gid: 62021}}
	raw[8].stat = unix.Stat_t{Mode: unix.S_IFREG | 0400}
	raw[9].stat.Mode = unix.S_IFIFO | 0600
	for i := range 2 {
		raw[i+10] = raw[i+6]
		raw[i+10].flags = unix.O_PATH
		raw[i+10].fs.Flags = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
		if i == 0 {
			raw[i+10].fs.Flags |= unix.ST_RDONLY
		}
	}
	raw[12] = routedDHCPServerRawFDV2{stat: unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFDIR | 0755}, fs: unix.Statfs_t{Type: unix.CGROUP2_SUPER_MAGIC}}
	return b, raw
}

const nativeDHCPServerRawFDEndProbeV2 = "--andeiva-test-kea-raw-fd-end"

// The test-only probe checks descriptor flags before m.Run opens any files.
func init() {
	if len(os.Args) != 4 || os.Args[1] != nativeDHCPServerRawFDEndProbeV2 {
		return
	}
	pins, err := strconv.Atoi(os.Args[2])
	if err != nil || (pins != 1 && pins != 2) || (os.Args[3] != "inspect" && os.Args[3] != "local") {
		os.Exit(2)
	}
	nextFD := 12 + pins
	if os.Args[3] == "local" {
		fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, nextFD)
		if err != nil || fd != nextFD {
			fmt.Fprintln(os.Stderr, "could not create local close-on-exec descriptor", fd, err)
			os.Exit(2)
		}
	}
	flags, err := unix.FcntlInt(uintptr(nextFD), unix.F_GETFD, 0)
	if err == unix.EBADF {
		fmt.Print("closed ")
	} else if err == nil && flags == unix.FD_CLOEXEC {
		fmt.Print("local ")
	} else if err == nil && flags == 0 {
		target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(nextFD))
		fmt.Print("inherited ", target, " ")
	} else {
		fmt.Fprintln(os.Stderr, "unexpected descriptor flags", flags, err)
		os.Exit(2)
	}
	if err := checkRoutedDHCPServerRawFDEndV2(pins); errors.Is(err, ErrIdentity) {
		fmt.Println("rejected")
	} else if err == nil {
		fmt.Println("accepted")
	} else {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestRoutedDHCPServerRawMountContractV2RejectsExtraSlot(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Launch real exec children with closed, locally created, and inherited
	// descriptors at the first slot past the sealed layout.
	for _, pins := range []int{1, 2} {
		for _, tc := range []struct {
			mode, want string
			extra      bool
			defaultCPU bool
		}{
			{mode: "inspect", want: "closed accepted\n"},
			{mode: "local", want: "local accepted\n"},
			{mode: "inspect", want: "inherited /dev/null rejected\n", extra: true, defaultCPU: true},
		} {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			cmd := exec.CommandContext(ctx, executable, nativeDHCPServerRawFDEndProbeV2, strconv.Itoa(pins), tc.mode)
			cmd.Env = []string{"LC_ALL=C"}
			if !tc.defaultCPU {
				// Make the kernel's empty slot deterministic. The local case
				// fills it after exec with a close-on-exec duplicate.
				cmd.Env = append(cmd.Env, "GODEBUG=containermaxprocs=0")
			}
			fileCount := 9 + pins
			if tc.extra {
				fileCount++
			}
			cmd.ExtraFiles = make([]*os.File, fileCount)
			for i := range cmd.ExtraFiles {
				cmd.ExtraFiles[i] = f
			}
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil || string(out) != tc.want {
				t.Errorf("pins=%d mode=%s extra=%v: got %q, want %q, err=%v", pins, tc.mode, tc.extra, out, tc.want, err)
			}
		}
	}
}

func TestRoutedDHCPServerRawMountContractV2(t *testing.T) {
	b, raw := serverRawFixtureV2()
	if err := validateRoutedDHCPServerRawFDsV2(b, raw); err != nil {
		t.Fatal("valid complete model", err)
	}
	two := b
	two.ServiceCgroups = append(append([]routedDHCPServerCgroupWireV1(nil), b.ServiceCgroups...), routedDHCPServerCgroupWireV1{Role: "wan", Name: "dhcp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Device: 1, Inode: 3})
	withTwo := raw
	withTwo[13] = withTwo[12]
	withTwo[13].stat.Ino = 3
	if err := validateRoutedDHCPServerRawFDsV2(two, withTwo); err != nil {
		t.Fatal("valid two-slot model", err)
	}
	withTwo[13] = routedDHCPServerRawFDV2{}
	if validateRoutedDHCPServerRawFDsV2(two, withTwo) == nil {
		t.Fatal("missing second service slot accepted")
	}
	for _, tt := range []struct {
		name string
		edit func(*routedDHCPServerBootstrapV2, *[14]routedDHCPServerRawFDV2)
	}{
		{"missing config", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[6] = routedDHCPServerRawFDV2{} }},
		{"extra cgroup slot", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[13] = r[12] }},
		{"missing tree", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[10] = routedDHCPServerRawFDV2{}
		}},
		{"missing second tree", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[11] = routedDHCPServerRawFDV2{}
		}},
		{"poller substituted", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[10].stat.Mode = unix.S_IFIFO | 0600
		}},
		{"swapped trees", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10], r[11] = r[11], r[10] }},
		{"aliased tree", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[11] = r[10] }},
		{"tree is ordinary original", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10] = r[6] }},
		{"foreign inode", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10].stat.Ino++ }},
		{"foreign device", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10].stat.Dev++ }},
		{"foreign owner", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10].stat.Uid++ }},
		{"forged source record", func(b *routedDHCPServerBootstrapV2, _ *[14]routedDHCPServerRawFDV2) {
			b.MountPins = append([]routedDHCPServerMountWireV2(nil), b.MountPins...)
			b.MountPins[0].Inode++
		}},
		{"writable config", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[10].fs.Flags &^= unix.ST_RDONLY
		}},
		{"readonly leases", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[11].fs.Flags |= unix.ST_RDONLY }},
		{"no nodev", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[10].fs.Flags &^= unix.ST_NODEV }},
		{"no noexec", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[11].fs.Flags &^= unix.ST_NOEXEC
		}},
		{"no nosuid", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[11].fs.Flags &^= unix.ST_NOSUID
		}},
		{"wrong namespace", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[5].namespace = unix.CLONE_NEWNET
		}},
		{"foreign host mount", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[5].stat.Ino++ }},
		{"wrong cgroup inode", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[12].stat.Ino++ }},
		{"writable cgroup", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[12].flags = unix.O_RDWR }},
		{"cgroup in wrong slot", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) {
			r[12] = routedDHCPServerRawFDV2{}
		}},
		{"writable lifetime pipe", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[9].flags = unix.O_WRONLY }},
		{"path-only lifetime pipe", func(_ *routedDHCPServerBootstrapV2, r *[14]routedDHCPServerRawFDV2) { r[9].flags = unix.O_PATH }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			candidate := b
			observed := raw
			tt.edit(&candidate, &observed)
			if validateRoutedDHCPServerRawFDsV2(candidate, observed) == nil {
				t.Fatal("invalid inherited contract accepted")
			}
		})
	}
}

// Exact former wire shape and version gate, retained only for compatibility
// evidence. Its positive control prevents unconditional-rejection false passes.
type serverLegacyBootstrapV1 struct {
	Version            int                             `json:"version"`
	ParentPID          int                             `json:"parent_pid"`
	ParentStartTicks   uint64                          `json:"parent_start_ticks"`
	HostMountNamespace uint64                          `json:"host_mount_namespace"`
	DeadlineBootNS     int64                           `json:"deadline_boot_ns"`
	Metadata           Metadata                        `json:"metadata"`
	Config             dhcpserver.Config               `json:"config"`
	Bindings           []routedDHCPServerBindingWireV1 `json:"bindings"`
	ServiceCgroups     []routedDHCPServerCgroupWireV1  `json:"service_cgroups"`
	LeaseBudgetBytes   int64                           `json:"lease_budget_bytes"`
}

func TestRoutedDHCPServerBootstrapPeerMismatchV2(t *testing.T) {
	b := serverBootstrapFixtureV2()
	current, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	legacy := serverLegacyBootstrapV1{1, b.ParentPID, b.ParentStartTicks, b.HostMountNamespace, b.DeadlineBootNS, b.Metadata, b.Config, b.Bindings, b.ServiceCgroups, b.LeaseBudgetBytes}
	old, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	readOld := func(raw []byte) bool {
		var v serverLegacyBootstrapV1
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(&v) == nil && d.Decode(new(any)) == io.EOF && v.Version == 1
	}
	if !readOld(old) || readOld(current) {
		t.Fatal("former codec compatibility gate")
	}
	if _, err := decodeRoutedDHCPServerBootstrapV2(current); err != nil {
		t.Fatal("current positive control", err)
	}
	if _, err := decodeRoutedDHCPServerBootstrapV2(old); err == nil {
		t.Fatal("legacy wire accepted by current peer")
	}
	for _, raw := range [][]byte{
		bytes.Replace(current, []byte(`"version":2`), []byte(`"version":1`), 1),
		bytes.Replace(current, []byte(`"version":2`), []byte(`"Version":2`), 1),
		bytes.Replace(current, []byte(`"version":2`), []byte(`"version":2,"Version":2`), 1),
		bytes.Replace(current, []byte(`"mount_pins":[`), []byte(`"unknown":1,"mount_pins":[`), 1),
		append(current, []byte(" null")...),
	} {
		if _, err := decodeRoutedDHCPServerBootstrapV2(raw); err == nil {
			t.Fatal("noncanonical or mixed peer wire accepted")
		}
	}
	for _, pins := range [][]routedDHCPServerMountWireV2{nil, {}, b.MountPins[:1], {b.MountPins[1], b.MountPins[0]}, {b.MountPins[0], b.MountPins[0]}, append(append([]routedDHCPServerMountWireV2(nil), b.MountPins...), b.MountPins[0])} {
		candidate := b
		candidate.MountPins = pins
		raw, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRoutedDHCPServerBootstrapV2(raw); err == nil {
			t.Fatal("missing/extra/aliased/swapped mount pins accepted")
		}
	}
	for _, mutate := range []func(*routedDHCPServerBootstrapV2){
		func(v *routedDHCPServerBootstrapV2) { v.ParentStartTicks = 0 },
		func(v *routedDHCPServerBootstrapV2) { v.ParentPID = 1 },
		func(v *routedDHCPServerBootstrapV2) { v.DeadlineBootNS = 0 },
		func(v *routedDHCPServerBootstrapV2) { v.HostMountNamespace = 0 },
		func(v *routedDHCPServerBootstrapV2) {
			v.ServiceCgroups = append(append([]routedDHCPServerCgroupWireV1(nil), v.ServiceCgroups...), v.ServiceCgroups[0])
		},
		func(v *routedDHCPServerBootstrapV2) { v.ServiceCgroups = nil },
	} {
		candidate := b
		mutate(&candidate)
		raw, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRoutedDHCPServerBootstrapV2(raw); err == nil {
			t.Fatal("invalid bootstrap provenance/topology accepted")
		}
	}
	if RunRoutedDHCPServerRoleV1(context.Background()) != ErrIdentity || RunRoutedDHCPServerRoleV2(nil) != ErrIdentity {
		t.Fatal("retired or unassembled role accepted")
	}
}

func TestRoutedDHCPServerMountOwnershipV2(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("unprivileged preparation failure fixture")
	}
	file, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if pins, wire, err := prepareRoutedDHCPServerMountPinsV2(nil, directory); err != ErrIdentity || pins != nil || wire != nil {
		t.Fatal("missing original accepted", err)
	}
	if pins, wire, err := prepareRoutedDHCPServerMountPinsV2(directory, directory); err != ErrIdentity || pins != nil || wire != nil {
		t.Fatal("wrong original type accepted", err)
	}
	if pins, wire, err := prepareRoutedDHCPServerMountPinsV2(file, directory); err == nil || pins != nil || wire != nil {
		if pins != nil {
			_ = pins.closeV2()
		}
		t.Fatal("unprivileged detached preparation unexpectedly succeeded", err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("borrowed source was closed", err)
	}
	if _, err := directory.Stat(); err != nil {
		t.Fatal("borrowed leases were closed", err)
	}
	owned, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	p := &routedDHCPServerMountPinsV2{configuration: owned}
	if err := p.closeV2(); err != nil || p.configuration != nil {
		t.Fatal("owned close failed", err)
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("owned descriptor remains open")
	}
	if err := p.closeV2(); err != nil {
		t.Fatal("empty close not idempotent", err)
	}
	closed, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	p.configuration = closed
	if err := p.closeV2(); !errors.Is(err, os.ErrClosed) || p.configuration != nil {
		t.Fatal("cleanup failure lost", err)
	}
	tree := file
	if attachRoutedDHCPServerMountV2(&tree, file, "/arbitrary", true) != ErrIdentity || tree != file {
		t.Fatal("arbitrary target accepted or borrowed descriptor changed")
	}
	if attachRoutedDHCPServerMountV2(&tree, file, routedDHCPServerConfigV1, true) != ErrIdentity || tree != file {
		t.Fatal("ordinary descriptor accepted as detached mount")
	}
}

func TestRoutedDHCPServerFixedMountAttributesV2(t *testing.T) {
	for _, ro := range []bool{true, false} {
		a := routedDHCPServerMountAttributesV2(ro)
		want := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC)
		if ro {
			want |= unix.MOUNT_ATTR_RDONLY
		}
		if a.Attr_set != want || a.Propagation != 0 || a.Userns_fd != 0 || ro && a.Attr_clr != 0 || !ro && a.Attr_clr != unix.MOUNT_ATTR_RDONLY {
			t.Fatal("fixed mount attributes changed")
		}
	}
	b, raw := serverRawFixtureV2()
	before := raw
	if err := validateRoutedDHCPServerRawFDsV2(b, raw); err != nil || !reflect.DeepEqual(before, raw) {
		t.Fatal("pure validation mutated observation", err)
	}
}

func TestRoutedDHCPServerMountDescriptorEvidenceV2(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("ino: 61\n"), []byte("flags: 02000000\nflags: 0\n"), []byte("flags: bogus\n"), []byte("flags: 08\n"), []byte("flags: 0 extra\n")} {
		if _, err := serverLifecycleFDFlagsV2(raw); err == nil {
			t.Fatal("missing/ambiguous descriptor flags accepted")
		}
	}
	if flags, err := serverLifecycleFDFlagsV2([]byte("pos:\t0\nflags:\t012000000\nmnt_id:\t23\nino:\t61\n")); err != nil || flags&unix.O_PATH == 0 {
		t.Fatal("O_PATH evidence not recognized", err)
	}
}
