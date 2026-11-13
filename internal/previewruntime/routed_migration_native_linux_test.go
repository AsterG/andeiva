//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"golang.org/x/sys/unix"
)

var migrationSourceNativeV3 = flag.Bool("andeiva-native-migration-source-v3", false, "explicitly qualify the retained deployed source without applying policy")

const migrationSourceNativeInputV3 = RuntimeDir + "/migration-source-qualification.json"
const migrationSourceNativeLockRoleV3 = "--andeiva-test-migration-source-lock-v3"
const migrationSourceNativeUIDRoleV3 = "--andeiva-test-migration-source-uid-v3"

type migrationSourceNativeInputRecordV3 struct {
	Version  int                `json:"version"`
	Firewall configpoc.Revision `json:"firewall"`
}
type migrationSourceNativeLockedV3 struct {
	Version     int                           `json:"version"`
	Request     string                        `json:"request"`
	Fingerprint configpoc.LegacyFingerprintV2 `json:"fingerprint"`
}

func runMigrationSourceNativeRoleV3(ctx context.Context, negative bool) error {
	var stat unix.Stat_t
	if unix.Fstat(0, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || stat.Uid != 0 || unix.SetNonblock(0, true) != nil {
		return ErrIdentity
	}
	input := os.NewFile(0, "native-source-request")
	if input == nil {
		return ErrIdentity
	}
	defer input.Close()
	if input.SetReadDeadline(time.Now().Add(45*time.Second)) != nil {
		return ErrUnavailable
	}
	reader := bufio.NewReaderSize(input, routedMigrationRequestLimitV3)
	data, err := reader.ReadSlice('\n')
	var request routedMigrationRequestV3
	if err != nil || firewallipc.Decode(data, &request) != nil || request.Version != 1 || request.ParentPID != os.Getppid() || checkPrivileges(request.Identities, false) != nil {
		return ErrIdentity
	}
	gateway := os.NewFile(3, "native-source-gateway")
	if gateway == nil {
		return ErrIdentity
	}
	defer gateway.Close()
	if verifyRoutedMigrationScopeV3(gateway, request.Metadata, false) != nil {
		return ErrIdentity
	}
	if negative {
		v := &routedMigrationVerifierV3{gateway: gateway, metadata: request.Metadata, identities: request.Identities}
		if err = v.VerifyMigratedSources(ctx, request.Expected, request.Firewall, request.Local); !errors.Is(err, ErrIdentity) {
			return ErrUnavailable
		}
		return nil
	}
	area, err := os.OpenRoot(DataDir + "/state")
	if err != nil {
		return err
	}
	defer area.Close()
	digest := sha256.Sum256(data)
	return configpoc.WithLegacyFingerprintV3(ctx, area, "firewall", func(ctx context.Context, fp configpoc.LegacyFingerprintV2) error {
		if err := json.NewEncoder(os.Stdout).Encode(migrationSourceNativeLockedV3{Version: 1, Request: hex.EncodeToString(digest[:]), Fingerprint: fp}); err != nil {
			return err
		}
		release, err := reader.ReadSlice('\n')
		if err != nil || string(release) != "release\n" || ctx.Err() != nil {
			return ErrUnavailable
		}
		return nil
	})
}

func TestRoutedMigrationSourceNativeV3(t *testing.T) {
	if !*migrationSourceNativeV3 {
		t.Skip("requires explicit retained-source qualification, three deployed identities and API/socket stopped")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root supervisor identity required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := LoadConfig(ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ReadMetadata()
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := readOwned(migrationSourceNativeInputV3, 0, 0, 0600, routedMigrationRequestLimitV3)
	if err != nil {
		t.Fatal(err)
	}
	var input migrationSourceNativeInputRecordV3
	if firewallipc.Decode(bytes, &input) != nil || input.Version != 1 {
		t.Fatal("invalid qualification input")
	}
	fw, err := configpoc.Canonical(input.Firewall.Config)
	if err != nil || fw.Hash != input.Firewall.Hash || fw.Config.SchemaVersion != 4 {
		t.Fatal("canonical schema4 source required")
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := os.OpenFile(RuntimeDir+"/netns/gateway", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	if verifyRoutedMigrationScopeV3(gateway, metadata, false) != nil {
		t.Fatal("invalid retained namespace")
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("root-owned executable and ancestry required")
	}
	request := routedMigrationRequestV3{Version: 1, ParentPID: os.Getpid(), Metadata: metadata, Identities: ids, Expected: [2]configpoc.LegacyFingerprintV2{{Domain: "firewall"}, {Domain: "local_services"}}, Firewall: fw, Local: local}
	start := func(role string) (*exec.Cmd, *os.File, *bufio.Reader) {
		t.Helper()
		read, write, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		args := []string{"--reuid=" + strconv.FormatUint(uint64(ids.APIUID), 10), "--regid=" + strconv.FormatUint(uint64(ids.APIGID), 10), "--groups=" + strconv.FormatUint(uint64(ids.IPCGID), 10), "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, role}
		command := exec.CommandContext(ctx, "/usr/bin/setpriv", args...)
		command.Stdin = read
		command.ExtraFiles = []*os.File{gateway}
		command.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		command.Stderr = os.Stderr
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		stdout, e := command.StdoutPipe()
		if e != nil {
			read.Close()
			write.Close()
			t.Fatal(e)
		}
		if e = command.Start(); e != nil {
			read.Close()
			write.Close()
			stdout.Close()
			t.Fatal(e)
		}
		read.Close()
		t.Cleanup(func() { write.Close(); _ = command.Process.Kill(); _ = command.Wait(); stdout.Close() })
		if e = json.NewEncoder(write).Encode(request); e != nil {
			t.Fatal(e)
		}
		return command, write, bufio.NewReaderSize(stdout, 4096)
	}
	// This real APIUID worker holds the original legacy lock during every
	// supplier observation. It never opens the journal as root or changes it.
	worker, control, output := start(migrationSourceNativeLockRoleV3)
	line, err := output.ReadSlice('\n')
	if err != nil {
		t.Fatal("source lock not acquired", err)
	}
	var held migrationSourceNativeLockedV3
	encoded, _ := json.Marshal(request)
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	if firewallipc.Decode(line, &held) != nil || held.Version != 1 || held.Request != hex.EncodeToString(digest[:]) || held.Fingerprint.Domain != "firewall" || held.Fingerprint.Source == "" {
		t.Fatal("source fingerprint correlation failed")
	}
	request.Expected[0] = held.Fingerprint
	v := &routedMigrationVerifierV3{gateway: gateway, metadata: metadata, identities: ids}
	if err = v.VerifyMigratedSources(ctx, request.Expected, fw, local); err != nil {
		t.Fatal("actual supplier verification failed", err)
	}
	// Wrong UID receives the same valid scope/revisions/FD and must fail before
	// launching privileged inspection. No relaxation of source permissions.
	negative, negativeInput, _ := start(migrationSourceNativeUIDRoleV3)
	if err = negativeInput.Close(); err != nil {
		t.Fatal(err)
	}
	if err = negative.Wait(); err != nil {
		t.Fatal("wrong-UID denial failed", err)
	}
	ordinary, err := os.CreateTemp(t.TempDir(), "not-a-namespace-")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	foreign := &routedMigrationVerifierV3{gateway: ordinary, metadata: metadata, identities: ids}
	if err = foreign.VerifyMigratedSources(ctx, request.Expected, fw, local); !errors.Is(err, ErrIdentity) {
		t.Fatal("ordinary descriptor accepted", err)
	}
	if _, err = io.WriteString(control, "release\n"); err != nil {
		t.Fatal(err)
	}
	if err = control.Close(); err != nil {
		t.Fatal(err)
	}
	if err = worker.Wait(); err != nil {
		t.Fatal("source changed or lock cleanup failed", err)
	}
	t.Log("PASS: actual APIUID source lock, capless guardian probes, NET_ADMIN semantic inspection, empty IPv4/IPv6 INET listener profile and UID/FD denials; no migration, writes, traffic or new gateway qualification")
}
