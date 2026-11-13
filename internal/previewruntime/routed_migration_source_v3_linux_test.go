//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

func migrationSourceFixtureV3(t *testing.T) (*routedTestKernel, configpoc.Revision, configpoc.Revision, [2]configpoc.LegacyFingerprintV2) {
	t.Helper()
	var rules []configpoc.Rule
	for _, protocol := range []string{"tcp", "udp"} {
		enabled := protocol == "tcp"
		rules = append(rules, configpoc.Rule{ID: "retained-" + protocol, Enabled: &enabled, Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: protocol, SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}})
	}
	fw, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}})
	if err != nil {
		t.Fatal(err)
	}
	kernel := &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
	artifact, err := firewallnft.Compile(fw.Config)
	if err != nil {
		t.Fatal(err)
	}
	// Kernel I/O is explicitly simulated; compiler and semantic inspection are real.
	if err = kernel.Apply(context.Background(), artifact.Create); err != nil {
		t.Fatal(err)
	}
	return kernel, fw, local, [2]configpoc.LegacyFingerprintV2{{Domain: "firewall"}, {Domain: "local_services"}}
}

func TestRoutedMigrationSourceV3SemanticReadOnly(t *testing.T) {
	kernel, fw, local, expected := migrationSourceFixtureV3(t)
	if err := verifyMigrationSourceFixtureV3(context.Background(), kernel, expected, fw, local); err != nil {
		t.Fatal(err)
	}
	if len(kernel.batches) != 1 || len(fw.Config.Rules) != 2 {
		t.Fatal("migration readback changed policy")
	}
	for _, which := range []routedactivation.Table{routedactivation.LocalTable, routedactivation.RoutedTable} {
		kernel.objects[which] = []map[string]any{}
		if err := verifyMigrationSourceFixtureV3(context.Background(), kernel, expected, fw, local); err == nil {
			t.Fatal("existing managed table treated as absent", which)
		}
		delete(kernel.objects, which)
	}
	kernel.readFail = true
	if err := verifyMigrationSourceFixtureV3(context.Background(), kernel, expected, fw, local); err == nil {
		t.Fatal("read failure treated as absence")
	}
}

type migrationObserveMutationV3 struct {
	kernel *routedTestKernel
	calls  int
}

func (m *migrationObserveMutationV3) Observe(ctx context.Context, table routedactivation.Table) ([]byte, bool, error) {
	m.calls++
	if m.calls == 4 {
		// Keep comments/IDs while removing one effective rule before the final read.
		objects := m.kernel.objects[routedactivation.LegacyTable]
		m.kernel.objects[routedactivation.LegacyTable] = objects[:len(objects)-1]
	}
	return m.kernel.Observe(ctx, table)
}
func TestRoutedMigrationSourceV3DetectsChangedReadback(t *testing.T) {
	kernel, fw, local, expected := migrationSourceFixtureV3(t)
	observer := &migrationObserveMutationV3{kernel: kernel}
	if err := verifyMigrationSourceFixtureV3(context.Background(), observer, expected, fw, local); err == nil || observer.calls != 4 {
		t.Fatal("changed physical policy accepted", err, observer.calls)
	}
}
func TestRoutedMigrationSourceV3RejectsInvalidInputsAndForeignClaims(t *testing.T) {
	kernel, fw, local, expected := migrationSourceFixtureV3(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if verifyMigrationSourceFixtureV3(ctx, kernel, expected, fw, local) == nil || verifyMigrationSourceFixtureV3(nil, kernel, expected, fw, local) == nil {
		t.Fatal("cancel/nil accepted")
	}
	bad := fw
	bad.Hash = "foreign"
	if verifyMigrationSourceFixtureV3(context.Background(), kernel, expected, bad, local) == nil {
		t.Fatal("forged revision accepted")
	}
	expected[0].Domain = "local_services"
	if verifyMigrationSourceFixtureV3(context.Background(), kernel, expected, fw, local) == nil {
		t.Fatal("wrong domain accepted")
	}
	if err := (*routedMigrationVerifierV3)(nil).VerifyMigratedSources(context.Background(), expected, fw, local); err == nil {
		t.Fatal("nil source accepted")
	}
	if err := RunRoutedMigrationSourceRoleV3(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	var output routedMigrationOutputV3
	if _, err := output.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{1}); err == nil || output.Len() != 4096 {
		t.Fatal("output bound ignored")
	}
	// An ordinary process cannot invoke the role by choosing a user-controlled
	// request path: the fixed role requires root-created stdin and a namespace FD.
	if os.Getuid() != 0 {
		if err := (&routedMigrationVerifierV3{}).VerifyMigratedSources(context.Background(), expected, fw, local); err == nil {
			t.Fatal("unprivileged launch accepted")
		}
	}
}

func TestRoutedMigrationSourceV3FixedRolePrivilegeArguments(t *testing.T) {
	ids := Identities{SchemaVersion: 1, APIUID: 1001, APIGID: 1002, HelperUID: 1003, IPCGID: 1004}
	for _, role := range []string{RoutedMigrationSourceRoleV3, RoutedMigrationStateRoleV3} {
		args, err := routedMigrationSourceArgsV3("/usr/bin/setpriv", ids, role)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if args[len(args)-1] != role || strings.Contains(joined, "Recovered") || strings.Contains(joined, "--reset-env") {
			t.Fatal(args)
		}
		if role == RoutedMigrationSourceRoleV3 {
			if args[0] != "--net=/proc/self/fd/3" || !strings.Contains(joined, "--reuid=1003 --regid=1004 --groups=1004 --bounding-set=-all,+net_admin") {
				t.Fatal(args)
			}
		} else if args[0] != "--reuid=1001" || strings.Contains(joined, "nsenter") || strings.Contains(joined, "+net_admin") || !strings.Contains(joined, "--bounding-set=-all --inh-caps=-all --ambient-caps=-all") {
			t.Fatal(args)
		}
	}
	if _, err := routedMigrationSourceArgsV3("/caller-selected", ids, RoutedMigrationSourceRoleV3); err == nil {
		t.Fatal("untrusted executable accepted")
	}
	if _, err := routedMigrationSourceArgsV3("/usr/bin/setpriv", ids, "apply"); err == nil {
		t.Fatal("unknown child role accepted")
	}
	if _, _, err := observeMigrationGuardianV3(nil, Metadata{}, ids, ""); err == nil {
		t.Fatal("invalid probe accepted")
	}
	if RunRoutedMigrationStateRoleV3(nil) == nil {
		t.Fatal("nil state role accepted")
	}
}

func verifyMigrationSourceFixtureV3(ctx context.Context, kernel routedMigrationKernelV3, expected [2]configpoc.LegacyFingerprintV2, fw, ls configpoc.Revision) error {
	return verifyRoutedMigrationSourceWithInetV3(ctx, kernel, expected, fw, ls, func(name string) ([]byte, error) { return migrationInetEmptyFixtureV3(name), nil })
}

func TestRoutedMigrationPinnedWorkerWaitsBeforeThreadExit(t *testing.T) {
	finished := make(chan error, 1)
	go func() {
		var result error
		defer func() { finished <- result }()
		tid := 0
		waited := false
		result = runPinnedMigrationCommandV3(func() error { tid = syscall.Gettid(); return nil }, func() error {
			for i := 0; i < 1000; i++ {
				runtime.Gosched()
				if syscall.Gettid() != tid {
					return errors.New("launching thread changed before Wait completed")
				}
			}
			waited = true
			return nil
		})
		if result == nil && !waited {
			result = errors.New("Wait was bypassed")
		}
		// Model a future job worker that retires its OS thread after finishing. It
		// cannot reach this point while the pinned command's Wait remains active.
		runtime.LockOSThread()
		runtime.Goexit()
	}()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	failed := errors.New("start refused")
	waited := false
	if err := runPinnedMigrationCommandV3(func() error { return failed }, func() error { waited = true; return nil }); !errors.Is(err, failed) || waited {
		t.Fatal("failed Start called Wait", err, waited)
	}
}
