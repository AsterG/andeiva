//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

const (
	nativeAccountsAPIRoleV3     = "--andeiva-native-accounts-api-v3"
	nativeAccountsHelperRoleV3  = "--andeiva-native-accounts-helper-v3"
	nativeAccountsReaderRoleV3  = "--andeiva-native-accounts-reader-v3"
	nativeAccountsMissingRoleV3 = "--andeiva-native-accounts-missing-v3"
)

var nativeAccountsV3 = flag.Bool("andeiva-native-accounts-v3", false, "root-only private-mount credential access qualification")

func nativeAccountsRoleV3(role string) error {
	uid, gid := os.Getuid(), os.Getgid()
	if role == nativeAccountsHelperRoleV3 || role == nativeAccountsReaderRoleV3 {
		wantUID, wantGID := 62002, 62003
		if role == nativeAccountsReaderRoleV3 {
			wantUID, wantGID = 62005, nativeReaderGIDV3
		}
		if uid != wantUID || gid != wantGID {
			return ErrIdentity
		}
		_, err := os.ReadFile(routedAccountsPathV3)
		if !errors.Is(err, os.ErrPermission) {
			return errors.New("private credential read was not denied")
		}
		return nil
	}
	if uid != 62001 || gid != 62001 {
		return ErrIdentity
	}
	accounts, err := loadRoutedAccountsV3(nativeIdentitiesV3)
	if role == nativeAccountsMissingRoleV3 {
		if err == nil {
			return errors.New("grouped loader fell back to legacy credentials")
		}
		return nil
	}
	if err != nil || len(accounts) != 2 {
		return ErrIdentity
	}
	credentials := os.NewFile(3, "private-test-credentials")
	defer credentials.Close()
	var secrets map[string]string
	if json.NewDecoder(io.LimitReader(credentials, 4096)).Decode(&secrets) != nil {
		return ErrIdentity
	}
	m, err := adminauth.New(accounts, func(adminauth.Event) error { return nil })
	if err != nil {
		return err
	}
	for _, account := range accounts {
		id, token, e := m.Login(account.Username, secrets[account.Username])
		if e != nil || id.Role != account.Role || id.SubjectID != account.SubjectID {
			return ErrIdentity
		}
		binding, e := m.ResolveSession(token)
		if e != nil {
			return e
		}
		subject, e := binding.Verify()
		if e != nil || subject.Role() != account.Role || subject.SubjectID() != account.SubjectID {
			return ErrIdentity
		}
	}
	return nil
}

func TestRoutedAccountsNativeV3(t *testing.T) {
	if !*nativeAccountsV3 {
		t.Skip("requires explicit root private-mount Debian laboratory")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root laboratory only")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, e1 := os.Stat("/proc/self/ns/mnt")
	host, e2 := os.Stat("/proc/1/ns/mnt")
	thread, e3 := os.Stat("/proc/thread-self/ns/mnt")
	if e1 != nil || e2 != nil || e3 != nil || os.SameFile(current, host) || !os.SameFile(current, thread) {
		t.Fatal("private mount namespace required")
	}
	if ownedDirectory(DataDir, 0, 0, 0755) != nil {
		t.Fatal("existing trusted mountpoint required")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", DataDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(DataDir, 0); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Mkdir(routedDeploymentDataV3, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(routedDeploymentDataV3, 0755); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{}
	var accounts []adminauth.Account
	for _, role := range []string{"admin", "viewer"} {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		credential := hex.EncodeToString(secret[:])
		digest := sha256.Sum256([]byte(credential))
		subject, err := configpoc.NewSubjectIDV2()
		if err != nil {
			t.Fatal(err)
		}
		secrets[role] = credential
		accounts = append(accounts, adminauth.Account{Username: role, Role: role, SubjectID: subject, CredentialRevision: hex.EncodeToString(digest[:]), CredentialSHA256: hex.EncodeToString(digest[:])})
	}
	image, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, image, 0440); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 62001); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0440); err != nil {
			t.Fatal(err)
		}
	}
	write(DataDir + "/accounts.json") // Valid alternative must never be an implicit fallback.
	legacyHash := sha256.Sum256(image)
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("trusted fixture binary required")
	}
	run := func(role, uid, gid, groups string, secret bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", "--reuid="+uid, "--regid="+gid, "--groups="+groups, "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, role) // #nosec G204 -- All roles and numeric identities are fixed test literals; no shell.
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		if secret {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			data, _ := json.Marshal(secrets)
			if _, e = w.Write(data); e != nil {
				_ = w.Close()
				t.Fatal(e)
			}
			if e = w.Close(); e != nil {
				t.Fatal(e)
			}
			cmd.ExtraFiles = []*os.File{r}
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native credential role failed: %s %v %s", role, err, output)
		}
	}
	run(nativeAccountsMissingRoleV3, "62001", "62001", "62003", false)
	write(routedAccountsPathV3)
	run(nativeAccountsAPIRoleV3, "62001", "62001", "62003", true)
	run(nativeAccountsHelperRoleV3, "62002", "62003", "62004", false)
	run(nativeAccountsReaderRoleV3, "62005", "62004", "62004", false)
	after, err := os.ReadFile(DataDir + "/accounts.json")
	if err != nil || sha256.Sum256(after) != legacyHash || !bytes.Equal(after, image) {
		t.Fatal("legacy credentials changed")
	}
	if data, err := os.ReadFile(routedAccountsPathV3); err != nil || !bytes.Equal(data, image) {
		t.Fatal("grouped credentials changed")
	}
	if strings.Contains(string(image), secrets["admin"]) || strings.Contains(string(image), secrets["viewer"]) {
		t.Fatal("plaintext credential persisted")
	}
	t.Log("native API reads/authenticates retained admin/viewer roles; helper and reader denied; absent grouped credentials reject legacy fallback; private tmpfs only, no HTTP RBAC or migration qualification")
}
