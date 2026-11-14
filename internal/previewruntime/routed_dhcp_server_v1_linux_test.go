//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"golang.org/x/sys/unix"
)

func TestRoutedDHCPServerCommandV1(t *testing.T) {
	for _, check := range []bool{false, true} {
		cmd := routedDHCPServerCommandV1(62020, 62021, check)
		want := []string{"/usr/bin/setpriv", "--reuid=62020", "--regid=62021", "--clear-groups", "--bounding-set=-all,+net_bind_service,+net_raw", "--inh-caps=-all,+net_bind_service,+net_raw", "--ambient-caps=-all,+net_bind_service,+net_raw", "--no-new-privs", "--pdeathsig=SIGKILL", "--apparmor-profile=kea-dhcp4", "--", "/usr/sbin/kea-dhcp4", "-c", "/etc/kea/kea-dhcp4.conf"}
		if check {
			want[4], want[5], want[6], want[9] = "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--apparmor-profile=kea-lfc"
			want = append(want[:11], "/usr/sbin/kea-lfc", "-4", "-d", "-p", "/var/lib/kea/kea-leases4.csv.pid", "-x", "/var/lib/kea/kea-leases4.csv.2", "-i", "/var/lib/kea/kea-leases4.csv.1", "-o", "/var/lib/kea/kea-leases4.csv.output", "-f", "/var/lib/kea/kea-leases4.csv.completed", "-c", "/etc/kea/kea-dhcp4.conf")
		}
		if !reflect.DeepEqual(cmd.Args, want) || cmd.Path != want[0] || len(cmd.ExtraFiles) != 0 || cmd.SysProcAttr.Pdeathsig != unix.SIGKILL || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}) {
			t.Fatal("engine launch boundary changed", cmd.Args)
		}
	}
}

func TestRoutedDHCPServerRefusesUnassembledRoleV1(t *testing.T) {
	if err := RunRoutedDHCPServerComponentV1(nil, RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := RunRoutedDHCPServerComponentV1(context.Background(), RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := routedDHCPServerScopeV1(RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := routedDHCPServerConfigFileV1(nil, nil); err != ErrIdentity {
		t.Fatal(err)
	}
}

func TestRoutedDHCPServerLeaseDiagnosticsV1(t *testing.T) {
	valid := "INFO [kea-lfc] LFC_READ_STATS Leases: 12, attempts: 13, errors: 0.\nINFO [kea-lfc] LFC_WRITE_STATS Leases: 10, attempts: 10, errors: 0.\nINFO [kea-lfc] LFC_TERMINATE LFC finished processing\n"
	for _, text := range []string{"", "LFC_TERMINATE", valid + "ERROR [kea-dhcpsrv] DHCPSRV_MEMFILE_LEASE_LOAD_ROW_ERROR corrupted row", valid + "WARN lease subnet mismatch", valid + "FATAL load failed", strings.Replace(valid, "errors: 0", "errors: 1", 1), valid + valid, strings.Replace(valid, "Leases: 12", "Leases: 18446744073709551616", 1)} {
		b := &routedDHCPServerLogV1{}
		if _, err := b.Write([]byte(text)); err != nil || b.clean() {
			t.Fatal("diagnostic admitted", err)
		}
	}
	b := &routedDHCPServerLogV1{}
	_, _ = b.Write([]byte(valid))
	if !b.clean() {
		t.Fatal("complete zero-error check refused")
	}
	before := len(b.data)
	if _, err := b.Write(bytes.Repeat([]byte{'x'}, dhcpkea.MaxArtifactBytes+1)); err == nil || b.clean() || len(b.data) != before {
		t.Fatal("unbounded log")
	}
}

func TestRoutedDHCPServerLeaseFilesV1(t *testing.T) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("unprivileged file-ownership test")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	check := func(want bool, budget int64) {
		t.Helper()
		err := routedDHCPServerLeasesV1(f, uid, gid, budget)
		if (err == nil) != want {
			t.Fatalf("allowed=%v error=%v", want, err)
		}
	}
	check(true, 1024)
	check(false, 0)
	if routedDHCPServerLeasesV1(f, uid+1, gid, 1024) == nil {
		t.Fatal("foreign owner")
	}
	lease := filepath.Join(dir, "kea-leases4.csv")
	if err := os.WriteFile(lease, []byte("Kea will validate content"), 0600); err != nil {
		t.Fatal(err)
	}
	check(true, 1024) // Filesystem validation makes no CSV-integrity claim.
	check(false, 1)
	if err := os.Chmod(lease, 0644); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Chmod(lease, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "kea-leases4.csv.1")
	if err := os.Link(lease, alias); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lease, alias); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(alias, 0600); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(dir, "kea-leases4.csv.pid")
	if err := os.WriteFile(pid, []byte("123"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	for _, name := range []string{"../kea-leases4.csv", "kea-leases4.csv.pid", "kea-leases6.csv", "kea-leases4.csv.3", "unknown", strings.Repeat("x", 512)} {
		if routedDHCPServerLeaseNameV1(name) {
			t.Fatal(name)
		}
	}
}
