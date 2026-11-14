package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPTConfigurationIsolation(t *testing.T) {
	c := aptConfig("/var/backups/andeiva-dhcp-offline/"+strings.Repeat("a", 64), "/var/lib/andeiva-dhcp-bundles/"+strings.Repeat("a", 64), strings.Repeat("a", 64), strings.Repeat("b", 64))
	for _, want := range []string{`Dir::Etc::main "/dev/null"`, `Dir::Etc::sourcelist "/dev/null"`, `::InfoFD "0"`, `::Version "3"`, `AllowUnauthenticated "false"`, `AllowInsecureRepositories "false"`, `Dir::Log::Terminal "/dev/null"`} {
		if !strings.Contains(c, want) {
			t.Fatal(want)
		}
	}
	for _, bad := range []string{"trusted=yes", "NoLocking", "AllowUnauthenticated \"true\"", "--force", "http:"} {
		if strings.Contains(c, bad) {
			t.Fatal(bad)
		}
	}
}
func TestPolicyOnlyKea(t *testing.T) {
	// Shell execution uses the actual fixed candidate, without installing a hook.
	for _, tc := range []struct {
		args []string
		code int
	}{{[]string{"kea-dhcp4-server", "start"}, 101}, {[]string{"--quiet", "kea-dhcp4-server.service", "restart"}, 101}, {[]string{"sshd", "start"}, 0}, {[]string{"kea-dhcp6-server", "start"}, 0}} {
		command := execPolicy(t, tc.args)
		if command != tc.code {
			t.Fatalf("%v: %d", tc.args, command)
		}
	}
}
func TestAPTLockRequiresRealManager(t *testing.T) {
	t.Setenv("APT_HOOK_INFO_FD", "0")
	t.Setenv("DPKG_FRONTEND_LOCKED", "true")
	if aptOwnsLock() == nil {
		t.Fatal("environment alone granted authority")
	}
}
func TestPersistentLogBound(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "log"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	w := &durableLog{file: f}
	data := []byte(strings.Repeat("x", 1<<20))
	for i := 0; i < 6; i++ {
		n, e := w.Write(data)
		if e != nil || n != len(data) {
			t.Fatal(n, e)
		}
	}
	st, _ := f.Stat()
	if st.Size() != 4<<20 || !w.overflow || w.failed {
		t.Fatal(st.Size(), w)
	}
}
func TestRootOnlyEffects(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("capless negative")
	}
	if runMain() == nil {
		t.Fatal("capless accepted")
	}
}
