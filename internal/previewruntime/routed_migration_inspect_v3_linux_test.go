//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

func TestRoutedMigrationInspectV3DraftCreatesNoHistoricalGrantOrCredentialOutput(t *testing.T) {
	credential := sha256.Sum256([]byte("fixture-only-not-a-live-credential"))
	accounts := []adminauth.Account{{Username: "admin-a", Role: "admin", CredentialSHA256: hex.EncodeToString(credential[:])}, {Username: "viewer", Role: "viewer", CredentialSHA256: hex.EncodeToString(credential[:])}}
	raw, _ := json.Marshal(accounts)
	sourceHash := sha256.Sum256(raw)
	digest := hex.EncodeToString(sourceHash[:])
	fp := configpoc.LegacyFingerprintV2{Domain: "firewall", Source: strings.Repeat("a", 64), Tip: strings.Repeat("b", 64), Sequence: 110, Projection: 110, ReceiptIndex: strings.Repeat("c", 64)}
	plan, err := inspectMigrationPlanV3(accounts, digest, fp)
	if err != nil || len(plan.Subjects) != 2 || len(plan.Bindings) != 0 {
		t.Fatal(plan, err)
	}
	if plan.Subjects[0].ID == plan.Subjects[1].ID || plan.Subjects[0].ID == accounts[0].Username || plan.Subjects[0].CredentialRevision == accounts[0].CredentialSHA256 || accounts[0].SubjectID != "" {
		t.Fatal("implicit ownership, credential-derived ID or account mutation")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "credential_sha256") || strings.Contains(string(encoded), accounts[0].CredentialSHA256) {
		t.Fatal("credential material entered draft", err)
	}
	if validateMigrationPlanV3(plan, accounts, digest, fp) != nil {
		t.Fatal("valid draft refused")
	}
	for _, mutate := range []func(*routedMigrationPlanV3){
		func(p *routedMigrationPlanV3) { p.Firewall.ReceiptIndex = strings.Repeat("d", 64) },
		func(p *routedMigrationPlanV3) { p.AccountsSHA256 = strings.Repeat("d", 64) },
		func(p *routedMigrationPlanV3) { p.Subjects = p.Subjects[:1] },
		func(p *routedMigrationPlanV3) { p.Subjects[0].Retired = true },
		func(p *routedMigrationPlanV3) { p.Subjects[0].ID = p.Subjects[1].ID },
		func(p *routedMigrationPlanV3) {
			p.Bindings = append(p.Bindings, configpoc.LegacyBindingV2{Actor: "admin-a"})
		},
	} {
		var changed routedMigrationPlanV3
		if json.Unmarshal(encoded, &changed) != nil {
			t.Fatal("fixture decode")
		}
		mutate(&changed)
		if validateMigrationPlanV3(changed, accounts, digest, fp) == nil {
			t.Fatal("stale/implicit/invalid draft accepted")
		}
	}
	if _, err = InspectRoutedMigrationV3(nil, Config{}); err == nil {
		t.Fatal("nil supervisor accepted")
	}
	if RunRoutedMigrationInspectRoleV3(nil) == nil {
		t.Fatal("nil child accepted")
	}
	if _, err = InspectRoutedMigrationV3(context.Background(), Config{}); err == nil {
		t.Fatal("invalid/nonroot launch accepted")
	}
}

func TestRoutedMigrationInspectV3ExtraDescriptors(t *testing.T) {
	if mode := os.Getenv("ANDEIVA_TEST_INSPECT_FDS"); mode != "" {
		// WSL's launcher injects unrelated PTY descriptors into the test process.
		// Remove them only in this disposable fixture; production rejects them.
		entries, _ := os.ReadDir("/proc/self/fd")
		for _, entry := range entries {
			target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
			if target == "/dev/ptmx" {
				fd, _ := strconv.Atoi(entry.Name())
				if fd > 3 {
					_ = unix.Close(fd)
				}
			}
		}
		err := checkMigrationInspectFDsV3()
		if (mode == "deny") != (err != nil) {
			inspectFDEnvironmentDiagnosticV3()
			os.Exit(2)
		}
		os.Exit(0)
	}
	for _, mode := range []string{"clean", "deny"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRoutedMigrationInspectV3ExtraDescriptors$")
			// The fixture exercises one descriptor policy, not inherited CI coverage,
			// tracing or automatic container CPU discovery. Production is unchanged.
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "GOMAXPROCS=2", "ANDEIVA_TEST_INSPECT_FDS=" + mode}
			if mode == "deny" {
				first, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				unexpected, err := os.CreateTemp(t.TempDir(), "untrusted-extra-")
				if err != nil {
					t.Fatal(err)
				}
				defer unexpected.Close()
				cmd.ExtraFiles = []*os.File{first, unexpected}
			}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatal("descriptor policy failed", err, string(output))
			}
		})
	}
}

func TestRoutedMigrationInspectV3DraftPublicationNeverReplaces(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	plan := routedMigrationPlanV3{Version: 1, State: "draft"}
	if err = publishMigrationInspectDraftV3(root, plan, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	before, err := root.ReadFile("grouped-migration-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "unapproved-replacement"
	if err = publishMigrationInspectDraftV3(root, plan, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("draft replaced")
	}
	after, err := root.ReadFile("grouped-migration-plan.json")
	if err != nil || string(before) != string(after) {
		t.Fatal("existing approval context changed", err)
	}
}

// Fixture-only diagnostics deliberately omit descriptor targets and file paths.
func inspectFDEnvironmentDiagnosticV3() {
	var limit unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_NOFILE, &limit)
	fmt.Fprintf(os.Stderr, "fixture descriptor policy: maxprocs=%d soft=%d hard=%d\n", runtime.GOMAXPROCS(0), limit.Cur, limit.Max)
	entries, _ := os.ReadDir("/proc/self/fd")
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		var info unix.Stat_t
		statErr := unix.Fstat(fd, &info)
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		fmt.Fprintf(os.Stderr, "fd=%d type=%#o flags=%#x stat_ok=%t flags_ok=%t\n", fd, info.Mode&unix.S_IFMT, flags, statErr == nil, flagErr == nil)
	}
}
