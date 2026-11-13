//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
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

const migrationPrepareFrameLimitV3 = 65536
const migrationPreparedPathV3 = "/etc/andeiva-preview/grouped-prepared.json"

type migrationPrepareRequestV3 struct {
	Version       int        `json:"version"`
	ParentPID     int        `json:"parent_pid"`
	Metadata      Metadata   `json:"metadata"`
	Identities    Identities `json:"identities"`
	Draft         []byte     `json:"draft"`
	Authorization []byte     `json:"authorization"`
}
type migrationPrepareFrameV3 struct {
	Version  int                              `json:"version"`
	Sequence int                              `json:"sequence"`
	Kind     string                           `json:"kind"`
	Request  string                           `json:"request"`
	Expected [2]configpoc.LegacyFingerprintV2 `json:"expected"`
	Firewall configpoc.Revision               `json:"firewall"`
	Local    configpoc.Revision               `json:"local"`
	Prepared *routedMigrationPreparedV3       `json:"prepared,omitempty"`
}
type migrationPrepareAckV3 struct {
	Version  int    `json:"version"`
	Sequence int    `json:"sequence"`
	Request  string `json:"request"`
}

type migrationPrepareProxyV3 struct {
	reader   *bufio.Reader
	session  string
	sequence int
}

func (p *migrationPrepareProxyV3) VerifyMigratedSources(ctx context.Context, expected [2]configpoc.LegacyFingerprintV2, fw, local configpoc.Revision) error {
	if ctx == nil || ctx.Err() != nil || p.sequence >= 5 {
		return ErrUnavailable
	}
	p.sequence++
	data := marshal(migrationPrepareFrameV3{Version: 1, Sequence: p.sequence, Kind: "verify", Request: p.session, Expected: expected, Firewall: fw, Local: local})
	if len(data) == 0 || len(data) >= migrationPrepareFrameLimitV3 {
		return ErrConfiguration
	}
	data = append(data, '\n')
	if _, err := os.Stdout.Write(data); err != nil {
		return err
	}
	line, err := p.reader.ReadSlice('\n')
	if err != nil || validateMigrationPrepareAckV3(line, p.sequence, data) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func migrationPrepareInputV3(ctx context.Context) (migrationPrepareRequestV3, *bufio.Reader, *os.File, string, error) {
	var request migrationPrepareRequestV3
	if ctx == nil || ctx.Err() != nil || checkMigrationInspectFDsV3() != nil {
		return request, nil, nil, "", ErrIdentity
	}
	var in, out unix.Stat_t
	flags, fe := unix.FcntlInt(0, unix.F_GETFL, 0)
	output, oe := unix.FcntlInt(1, unix.F_GETFL, 0)
	if fe != nil || oe != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || output&unix.O_ACCMODE != unix.O_WRONLY || unix.Fstat(0, &in) != nil || unix.Fstat(1, &out) != nil || in.Mode&unix.S_IFMT != unix.S_IFIFO || out.Mode&unix.S_IFMT != unix.S_IFIFO || in.Uid != 0 || out.Uid != 0 || (in.Dev == out.Dev && in.Ino == out.Ino) || unix.SetNonblock(0, true) != nil {
		return request, nil, nil, "", ErrIdentity
	}
	input := os.NewFile(0, "migration-prepare-control")
	if input == nil {
		return request, nil, nil, "", ErrIdentity
	}
	fail := func() (migrationPrepareRequestV3, *bufio.Reader, *os.File, string, error) {
		_ = input.Close()
		return request, nil, nil, "", ErrIdentity
	}
	if input.SetReadDeadline(time.Now().Add(180*time.Second)) != nil {
		return fail()
	}
	reader := bufio.NewReaderSize(input, migrationPrepareFrameLimitV3)
	raw, err := reader.ReadSlice('\n')
	if err != nil || !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &request) != nil || request.Version != 1 || request.ParentPID <= 1 || request.ParentPID != os.Getppid() || request.Identities.Validate() != nil || checkPrivileges(request.Identities, false) != nil {
		return fail()
	}
	parent, err := os.Open("/proc/" + strconv.Itoa(request.ParentPID) + "/status")
	if err != nil {
		return fail()
	}
	status, re := io.ReadAll(io.LimitReader(parent, 65537))
	ce := parent.Close()
	if re != nil || ce != nil || !rootRoutedParentStatusV3(status, request.ParentPID) || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || os.Getppid() != request.ParentPID {
		return fail()
	}
	gateway := os.NewFile(3, "migration-prepare-source-namespace")
	if gateway == nil {
		return fail()
	}
	defer gateway.Close()
	unix.CloseOnExec(3)
	if verifyRoutedMigrationScopeV3(gateway, request.Metadata, false) != nil {
		return fail()
	}
	hash := sha256.Sum256(raw)
	return request, reader, input, hex.EncodeToString(hash[:]), nil
}

// RunRoutedMigrationPrepareRoleV3 opens only the fixed old FW source and newly
// provisioned private roots. Privileged readback is a bounded parent callback.
func RunRoutedMigrationPrepareRoleV3(ctx context.Context) (result error) {
	request, reader, input, session, err := migrationPrepareInputV3(ctx)
	if err != nil {
		return err
	}
	defer input.Close()
	p, a, err := decodeMigrationAuthorizationV3(request.Authorization, request.Draft)
	if err != nil {
		return err
	}
	raw, err := readOwned(DataDir+"/accounts.json", 0, request.Identities.APIGID, 0440, 16384)
	if err != nil {
		return err
	}
	var accounts []adminauth.Account
	hash := sha256.Sum256(raw)
	if !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &accounts) != nil || validateMigrationPlanV3(p, accounts, hex.EncodeToString(hash[:]), p.Firewall) != nil {
		return ErrConfiguration
	}
	var roots [6]*os.Root
	defer func() {
		for _, root := range roots {
			if root != nil {
				result = errors.Join(result, root.Close())
			}
		}
	}()
	for i, name := range []string{DataDir + "/state", routedDeploymentDataV3 + "/local-origin", routedDeploymentDataV3 + "/state", routedDeploymentDataV3 + "/admission", routedDeploymentDataV3 + "/plan", routedDeploymentDataV3 + "/emergency"} {
		roots[i], err = os.OpenRoot(name)
		if err != nil {
			return err
		}
	}
	proxy := &migrationPrepareProxyV3{reader: reader, session: session}
	prepared, err := prepareMigrationRootsV3(ctx, roots, p, a, accounts, hex.EncodeToString(hash[:]), proxy, configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 32768})
	if err != nil {
		return err
	}
	actual, err := readOwned(DataDir+"/accounts.json", 0, request.Identities.APIGID, 0440, 16384)
	if err != nil || !bytes.Equal(raw, actual) {
		return ErrConfiguration
	}
	return json.NewEncoder(os.Stdout).Encode(migrationPrepareFrameV3{Version: 1, Sequence: proxy.sequence + 1, Kind: "prepared", Request: session, Prepared: &prepared})
}

// PrepareRoutedMigrationV3 prepares storage only. It never changes accounts,
// starts the new runtime or marks a prepared store active.
func PrepareRoutedMigrationV3(ctx context.Context, c Config) (out routedMigrationPreparedV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return out, ErrIdentity
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		return out, err
	}
	metadata, err := ReadMetadata()
	if err != nil {
		return out, err
	}
	draft, err := readOwned(routedMigrationPlanPathV3, 0, 0, 0600, 65536)
	if err != nil {
		return out, err
	}
	authorization, err := readOwned(routedMigrationAuthorizationPathV3, 0, 0, 0600, 65536)
	if err != nil {
		return out, err
	}
	p, a, err := decodeMigrationAuthorizationV3(authorization, draft)
	if err != nil {
		return out, err
	}
	raw, err := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if err != nil {
		return out, err
	}
	var accounts []adminauth.Account
	hash := sha256.Sum256(raw)
	if !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &accounts) != nil || validateMigrationPlanV3(p, accounts, hex.EncodeToString(hash[:]), p.Firewall) != nil {
		return out, ErrConfiguration
	}
	gateway, err := os.OpenFile(RuntimeDir+"/netns/gateway", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return out, err
	}
	defer gateway.Close()
	if verifyRoutedMigrationScopeV3(gateway, metadata, false) != nil {
		return out, ErrIdentity
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return out, ErrIdentity
	}
	inspected, err := InspectRoutedMigrationV3(ctx, c)
	if err != nil || inspected.PlanSHA256 != a.PlanSHA256 || inspected.Firewall != p.Firewall {
		return out, ErrConfiguration
	}
	if err = provisionMigrationPrivateRootsV3(ids); err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	read, write, err := os.Pipe()
	if err != nil {
		return out, err
	}
	defer read.Close()
	defer write.Close()
	args := []string{"--reuid=" + strconv.FormatUint(uint64(ids.APIUID), 10), "--regid=" + strconv.FormatUint(uint64(ids.APIGID), 10), "--groups=" + strconv.FormatUint(uint64(ids.IPCGID), 10), "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, RoutedMigrationPrepareRoleV3}
	// #nosec G204 -- Fixed setpriv/current trusted executable/role and validated numeric IDs, no caller paths or shell.
	command := exec.CommandContext(call, "/usr/bin/setpriv", args...)
	command.Stdin = read
	command.ExtraFiles = []*os.File{gateway}
	command.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 200 * time.Millisecond
	var diagnostic routedMigrationOutputV3
	command.Stderr = &diagnostic
	stdout, err := command.StdoutPipe()
	if err != nil {
		return out, err
	}
	defer stdout.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = command.Start(); err != nil {
		return out, err
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			result = errors.Join(result, command.Wait())
		}
	}()
	if err = read.Close(); err != nil {
		return out, err
	}
	request := marshal(migrationPrepareRequestV3{Version: 1, ParentPID: os.Getpid(), Metadata: metadata, Identities: ids, Draft: draft, Authorization: authorization})
	if len(request) == 0 || len(request) >= migrationPrepareFrameLimitV3 {
		return out, ErrConfiguration
	}
	request = append(request, '\n')
	sessionHash := sha256.Sum256(request)
	session := hex.EncodeToString(sessionHash[:])
	if _, err = write.Write(request); err != nil {
		return out, err
	}
	replyReader := bufio.NewReaderSize(stdout, migrationPrepareFrameLimitV3)
	verifier := &routedMigrationVerifierV3{gateway: gateway, metadata: metadata, identities: ids}
	for sequence := 1; sequence <= 6; sequence++ {
		line, e := replyReader.ReadSlice('\n')
		frame, decodeErr := decodeMigrationPrepareFrameV3(line, sequence, session)
		if e != nil || decodeErr != nil {
			return out, ErrUnavailable
		}
		if frame.Kind == "prepared" {
			if sequence != 6 || frame.Prepared == nil || validateMigrationPreparedV3(*frame.Prepared, a.PlanSHA256) != nil {
				return out, ErrConfiguration
			}
			out = *frame.Prepared
			if err = write.Close(); err != nil {
				return out, err
			}
			err = command.Wait()
			waited = true
			if err != nil || call.Err() != nil {
				return out, ErrUnavailable
			}
			actual, e := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
			if e != nil || !bytes.Equal(actual, raw) {
				return out, ErrConfiguration
			}
			root, e := os.OpenRoot("/etc/andeiva-preview")
			if e != nil {
				return out, e
			}
			defer root.Close()
			if err = writeNew(root, "grouped-prepared.json", marshal(out), 0600, 0, 0); err != nil {
				return out, err
			}
			return out, syncDirectory(root.Name())
		}
		if frame.Kind != "verify" || sequence > 5 || frame.Prepared != nil || frame.Expected[0] != p.Firewall {
			return out, ErrConfiguration
		}
		if err = verifier.VerifyMigratedSources(call, frame.Expected, frame.Firewall, frame.Local); err != nil {
			return out, err
		}
		digest := sha256.Sum256(line)
		if err = json.NewEncoder(write).Encode(migrationPrepareAckV3{Version: 1, Sequence: sequence, Request: hex.EncodeToString(digest[:])}); err != nil {
			return out, err
		}
	}
	return out, ErrUnavailable
}

func provisionMigrationPrivateRootsV3(ids Identities) error {
	if ids.Validate() != nil || os.Geteuid() != 0 {
		return ErrIdentity
	}
	// #nosec G301 -- Fixed root-owned traversal-only parent for distinct API/helper identities; every policy/history root remains private 0700 and files 0600.
	if err := os.Mkdir(routedDeploymentDataV3, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	if ownedDirectory(routedDeploymentDataV3, 0, 0, 0755) != nil {
		return ErrIdentity
	}
	base, err := os.OpenRoot(routedDeploymentDataV3)
	if err != nil {
		return err
	}
	defer base.Close()
	for _, name := range []string{"local-origin", "state", "admission", "plan", "emergency"} {
		if err = base.Mkdir(name, 0700); err != nil {
			return err
		}
		file, e := base.Open(name)
		if e != nil {
			return e
		}
		if !fenceNoACLV3(file, true) {
			_ = file.Close()
			return ErrIdentity
		}
		if e = file.Chown(int(ids.APIUID), int(ids.APIGID)); e != nil {
			_ = file.Close()
			return e
		}
		if e = file.Sync(); e != nil {
			_ = file.Close()
			return e
		}
		if e = file.Close(); e != nil {
			return e
		}
	}
	return syncDirectory(base.Name())
}

func validateMigrationPrepareAckV3(line []byte, sequence int, request []byte) error {
	var ack migrationPrepareAckV3
	hash := sha256.Sum256(request)
	if len(line) == 0 || len(line) > 4096 || !jsoncheck.UniqueControlFields(line) || firewallipc.Decode(line, &ack) != nil || ack.Version != 1 || ack.Sequence != sequence || ack.Request != hex.EncodeToString(hash[:]) {
		return ErrUnavailable
	}
	return nil
}
func decodeMigrationPrepareFrameV3(line []byte, sequence int, session string) (migrationPrepareFrameV3, error) {
	var frame migrationPrepareFrameV3
	if len(line) == 0 || len(line) >= migrationPrepareFrameLimitV3 || !jsoncheck.UniqueControlFields(line) || firewallipc.Decode(line, &frame) != nil || frame.Version != 1 || sequence < 1 || sequence > 6 || frame.Sequence != sequence || frame.Request != session || !validHex(session, 32) {
		return frame, ErrUnavailable
	}
	switch frame.Kind {
	case "verify":
		if sequence > 5 || frame.Prepared != nil {
			return frame, ErrUnavailable
		}
	case "prepared":
		if sequence != 6 || frame.Prepared == nil {
			return frame, ErrUnavailable
		}
	default:
		return frame, ErrUnavailable
	}
	return frame, nil
}
