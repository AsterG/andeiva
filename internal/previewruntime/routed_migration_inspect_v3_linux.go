//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const RoutedMigrationInspectRoleV3 = "--andeiva-routed-migration-inspect-v3"
const routedMigrationPlanPathV3 = "/etc/andeiva-preview/grouped-migration-plan.json"

type routedMigrationInspectRequestV3 struct {
	Version    int        `json:"version"`
	ParentPID  int        `json:"parent_pid"`
	Metadata   Metadata   `json:"metadata"`
	Identities Identities `json:"identities"`
}
type routedMigrationInspectReplyV3 struct {
	Version     int                           `json:"version"`
	Request     string                        `json:"request"`
	Fingerprint configpoc.LegacyFingerprintV2 `json:"fingerprint"`
}
type routedMigrationPlanV3 struct {
	Version        int                           `json:"version"`
	State          string                        `json:"state"`
	AccountsSHA256 string                        `json:"accounts_sha256"`
	Firewall       configpoc.LegacyFingerprintV2 `json:"firewall"`
	Subjects       []configpoc.SubjectV2         `json:"subjects"`
	Bindings       []configpoc.LegacyBindingV2   `json:"bindings"`
}
type MigrationInspectResultV3 struct {
	PlanSHA256 string                        `json:"plan_sha256"`
	Firewall   configpoc.LegacyFingerprintV2 `json:"firewall"`
	Subjects   []MigrationInspectSubjectV3   `json:"subjects"`
}
type MigrationInspectSubjectV3 struct {
	Login     string `json:"login"`
	SubjectID string `json:"subject_id"`
}

func inspectMigrationPlanV3(accounts []adminauth.Account, digest string, source configpoc.LegacyFingerprintV2) (routedMigrationPlanV3, error) {
	out := routedMigrationPlanV3{Version: 1, State: "draft", AccountsSHA256: digest, Firewall: source, Subjects: []configpoc.SubjectV2{}, Bindings: []configpoc.LegacyBindingV2{}}
	if !validHex(digest, 32) || source.Domain != "firewall" || source.Source == "" {
		return out, ErrConfiguration
	}
	if _, err := adminauth.New(accounts, func(adminauth.Event) error { return nil }); err != nil {
		return out, ErrConfiguration
	}
	for _, account := range accounts {
		id, revision := account.SubjectID, account.CredentialRevision
		var err error
		if id == "" {
			id, err = configpoc.NewSubjectIDV2()
			if err != nil {
				return out, err
			}
			var bytes [32]byte
			if _, err = rand.Read(bytes[:]); err != nil {
				return out, err
			}
			revision = hex.EncodeToString(bytes[:])
		}
		out.Subjects = append(out.Subjects, configpoc.SubjectV2{ID: id, Login: account.Username, CredentialRevision: revision})
	}
	return out, nil
}

// RunRoutedMigrationInspectRoleV3 is a capless APIUID installer reader. It
// retains the legacy lock until the root parent acknowledges durable draft
// publication, then rechecks the original fingerprint before releasing it.
func RunRoutedMigrationInspectRoleV3(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if checkMigrationInspectFDsV3() != nil {
		return ErrIdentity
	}
	var in, out unix.Stat_t
	inputFlags, e := unix.FcntlInt(0, unix.F_GETFL, 0)
	outputFlags, oe := unix.FcntlInt(1, unix.F_GETFL, 0)
	if e != nil || oe != nil || inputFlags&unix.O_ACCMODE != unix.O_RDONLY || outputFlags&unix.O_ACCMODE != unix.O_WRONLY || unix.Fstat(0, &in) != nil || unix.Fstat(1, &out) != nil || in.Mode&unix.S_IFMT != unix.S_IFIFO || out.Mode&unix.S_IFMT != unix.S_IFIFO || in.Uid != 0 || out.Uid != 0 || (in.Dev == out.Dev && in.Ino == out.Ino) || unix.SetNonblock(0, true) != nil {
		return ErrIdentity
	}
	input := os.NewFile(0, "migration-inspect-control")
	if input == nil {
		return ErrIdentity
	}
	defer input.Close()
	if input.SetReadDeadline(time.Now().Add(45*time.Second)) != nil {
		return ErrUnavailable
	}
	reader := bufio.NewReaderSize(input, 16384)
	data, e := reader.ReadSlice('\n')
	var request routedMigrationInspectRequestV3
	if e != nil || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &request) != nil || request.Version != 1 || request.ParentPID <= 1 || request.ParentPID != os.Getppid() || request.Identities.Validate() != nil || checkPrivileges(request.Identities, false) != nil {
		return ErrIdentity
	}
	parent, e := os.Open("/proc/" + strconv.Itoa(request.ParentPID) + "/status")
	if e != nil {
		return ErrIdentity
	}
	status, re := io.ReadAll(io.LimitReader(parent, 65537))
	ce := parent.Close()
	if re != nil || ce != nil || !rootRoutedParentStatusV3(status, request.ParentPID) || armMigrationParentDeathV3(request.ParentPID) != nil {
		return ErrIdentity
	}
	gateway := os.NewFile(3, "migration-inspect-source-namespace")
	if gateway == nil {
		return ErrIdentity
	}
	defer gateway.Close()
	unix.CloseOnExec(3)
	if verifyRoutedMigrationScopeV3(gateway, request.Metadata, false) != nil {
		return ErrIdentity
	}
	area, e := os.OpenRoot(DataDir + "/state")
	if e != nil {
		return e
	}
	defer area.Close()
	digest := sha256.Sum256(data)
	return configpoc.WithLegacyFingerprintV3(ctx, area, "firewall", func(ctx context.Context, fp configpoc.LegacyFingerprintV2) error {
		if e := json.NewEncoder(os.Stdout).Encode(routedMigrationInspectReplyV3{Version: 1, Request: hex.EncodeToString(digest[:]), Fingerprint: fp}); e != nil {
			return e
		}
		release, e := reader.ReadSlice('\n')
		if e != nil || string(release) != "release\n" || ctx.Err() != nil {
			return ErrUnavailable
		}
		return nil
	})
}

// InspectRoutedMigrationV3 writes only an O_EXCL operational draft. It does not
// update accounts, invent historical ownership, prepare a store or activate it.
func InspectRoutedMigrationV3(ctx context.Context, c Config) (out MigrationInspectResultV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return out, ErrIdentity
	}
	ids, e := LoadIdentities(c)
	if e != nil {
		return out, e
	}
	metadata, e := ReadMetadata()
	if e != nil {
		return out, e
	}
	gateway, e := os.OpenFile(RuntimeDir+"/netns/gateway", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return out, e
	}
	defer gateway.Close()
	if verifyRoutedMigrationScopeV3(gateway, metadata, false) != nil {
		return out, ErrIdentity
	}
	self, e := os.Executable()
	if e != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return out, ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	read, write, e := os.Pipe()
	if e != nil {
		return out, e
	}
	defer read.Close()
	defer write.Close()
	args := []string{"--reuid=" + strconv.FormatUint(uint64(ids.APIUID), 10), "--regid=" + strconv.FormatUint(uint64(ids.APIGID), 10), "--groups=" + strconv.FormatUint(uint64(ids.IPCGID), 10), "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, RoutedMigrationInspectRoleV3}
	// #nosec G204 -- Fixed executable and inspector role, root-owned current binary and validated numeric identities; no shell or caller paths.
	command := exec.CommandContext(call, "/usr/bin/setpriv", args...)
	command.Stdin = read
	command.ExtraFiles = []*os.File{gateway}
	command.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 200 * time.Millisecond
	var diagnostic routedMigrationOutputV3
	command.Stderr = &diagnostic
	stdout, e := command.StdoutPipe()
	if e != nil {
		return out, e
	}
	defer stdout.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e = command.Start(); e != nil {
		return out, e
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			result = errors.Join(result, command.Wait())
		}
	}()
	if e = read.Close(); e != nil {
		return out, e
	}
	request := routedMigrationInspectRequestV3{Version: 1, ParentPID: os.Getpid(), Metadata: metadata, Identities: ids}
	data, e := json.Marshal(request)
	if e != nil {
		return out, e
	}
	data = append(data, '\n')
	if _, e = write.Write(data); e != nil {
		return out, e
	}
	line, e := bufio.NewReaderSize(stdout, 4096).ReadSlice('\n')
	var reply routedMigrationInspectReplyV3
	digest := sha256.Sum256(data)
	if e != nil || firewallipc.Decode(line, &reply) != nil || reply.Version != 1 || reply.Request != hex.EncodeToString(digest[:]) || reply.Fingerprint.Domain != "firewall" || reply.Fingerprint.Source == "" {
		return out, ErrUnavailable
	}
	raw, e := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if e != nil {
		return out, e
	}
	var accounts []adminauth.Account
	if !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &accounts) != nil {
		return out, ErrConfiguration
	}
	accountHash := sha256.Sum256(raw)
	plan, e := inspectMigrationPlanV3(accounts, hex.EncodeToString(accountHash[:]), reply.Fingerprint)
	if e != nil {
		return out, e
	}
	// Existing drafts are retained. Reinspection does not rotate assigned IDs or
	// silently replace an operator's authorization context.
	if old, readErr := readOwned(routedMigrationPlanPathV3, 0, 0, 0600, 65536); readErr == nil {
		var existing routedMigrationPlanV3
		if !jsoncheck.UniqueControlFields(old) || firewallipc.Decode(old, &existing) != nil || validateMigrationPlanV3(existing, accounts, plan.AccountsSHA256, plan.Firewall) != nil {
			return out, ErrConfiguration
		}
		plan = existing
	} else {
		if _, statErr := os.Lstat(routedMigrationPlanPathV3); !os.IsNotExist(statErr) {
			return out, ErrStorage
		}
		root, openErr := os.OpenRoot("/etc/andeiva-preview")
		if openErr != nil {
			return out, openErr
		}
		createErr := publishMigrationInspectDraftV3(root, plan, 0, 0)
		closeErr := root.Close()
		if createErr != nil || closeErr != nil {
			return out, ErrStorage
		}
	}
	// Revalidate the account source while the worker still holds the FW lock.
	actual, e := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if e != nil || !bytes.Equal(raw, actual) {
		return out, ErrConfiguration
	}
	if _, e = io.WriteString(write, "release\n"); e != nil {
		return out, e
	}
	if e = write.Close(); e != nil {
		return out, e
	}
	e = command.Wait()
	waited = true
	if e != nil || call.Err() != nil {
		return out, ErrUnavailable
	}
	saved, e := readOwned(routedMigrationPlanPathV3, 0, 0, 0600, 65536)
	var final routedMigrationPlanV3
	if e != nil || !jsoncheck.UniqueControlFields(saved) || firewallipc.Decode(saved, &final) != nil || validateMigrationPlanV3(final, accounts, plan.AccountsSHA256, plan.Firewall) != nil || !bytes.Equal(marshal(final), marshal(plan)) {
		return out, ErrConfiguration
	}
	hash := sha256.Sum256(saved)
	out.PlanSHA256 = hex.EncodeToString(hash[:])
	out.Firewall = plan.Firewall
	for _, subject := range plan.Subjects {
		out.Subjects = append(out.Subjects, MigrationInspectSubjectV3{Login: subject.Login, SubjectID: subject.ID})
	}
	return out, nil
}
func validateMigrationPlanV3(plan routedMigrationPlanV3, accounts []adminauth.Account, digest string, source configpoc.LegacyFingerprintV2) error {
	if plan.Version != 1 || plan.State != "draft" || plan.AccountsSHA256 != digest || plan.Firewall != source || len(plan.Bindings) != 0 || len(plan.Subjects) != len(accounts) || len(accounts) == 0 {
		return ErrConfiguration
	}
	assigned := append([]adminauth.Account{}, accounts...)
	seen := map[string]bool{}
	for _, subject := range plan.Subjects {
		if subject.Retired || seen[subject.Login] {
			return ErrConfiguration
		}
		seen[subject.Login] = true
		found := false
		for i, account := range accounts {
			if account.Username != subject.Login {
				continue
			}
			if account.SubjectID != "" && (account.SubjectID != subject.ID || account.CredentialRevision != subject.CredentialRevision) {
				return ErrConfiguration
			}
			assigned[i].SubjectID = subject.ID
			assigned[i].CredentialRevision = subject.CredentialRevision
			found = true
		}
		if !found {
			return ErrConfiguration
		}
	}
	if _, err := adminauth.New(assigned, func(adminauth.Event) error { return nil }); err != nil {
		return ErrConfiguration
	}
	return nil
}

func checkMigrationInspectFDsV3() error {
	// This is process-local hardening of the dedicated child, never a host limit.
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil || limit.Max < 256 || unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 256, Max: 256}) != nil {
		return ErrIdentity
	}
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return ErrIdentity
	}
	entries, readErr := dir.ReadDir(257)
	own := int(dir.Fd())
	if readErr != nil && readErr != io.EOF {
		_ = dir.Close()
		return ErrIdentity
	}
	if len(entries) > 256 {
		_ = dir.Close()
		return ErrIdentity
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil || fd < 0 || fd >= 256 {
			_ = dir.Close()
			return ErrIdentity
		}
		if fd <= 3 || fd == own {
			continue
		}
		target, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e != nil || (target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]") {
			_ = dir.Close()
			return ErrIdentity
		}
	}
	if dir.Close() != nil {
		return ErrIdentity
	}
	return nil
}

func publishMigrationInspectDraftV3(area *os.Root, plan routedMigrationPlanV3, uid, gid uint32) error {
	if area == nil {
		return ErrStorage
	}
	data := marshal(plan)
	if len(data) == 0 || len(data) > 65536 {
		return ErrConfiguration
	}
	if writeNew(area, "grouped-migration-plan.json", data, 0600, uid, gid) != nil {
		return ErrStorage
	}
	return syncDirectory(area.Name())
}
