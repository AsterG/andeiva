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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"golang.org/x/sys/unix"
)

const nativeSeedRoleV3 = "--andeiva-native-seed-v3"
const nativeReaderGIDV3 = 62004
const nativeRetirementFileV3 = "fd-test-retirement-receipt"

var nativeIdentitiesV3 = Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}

// Test-only reexec dispatch. No role is installed in an appliance binary.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var err error
		switch os.Args[1] {
		case RoutedHelperRoleV3, RoutedAPIRoleV3:
			err = RunRoutedLaunchRoleV3(ctx, os.Args[1], nativeFactoriesV3())
		case RoutedMigrationPrepareRoleV3:
			err = RunRoutedMigrationPrepareRoleV3(context.Background())
		case RoutedMigrationInspectRoleV3:
			err = RunRoutedMigrationInspectRoleV3(ctx)
		case RoutedMigrationSourceRoleV3:
			err = RunRoutedMigrationSourceRoleV3(ctx)
		case RoutedMigrationStateRoleV3:
			err = RunRoutedMigrationStateRoleV3(ctx)
		case migrationSourceNativeLockRoleV3:
			err = runMigrationSourceNativeRoleV3(ctx, false)
		case migrationSourceNativeUIDRoleV3:
			err = runMigrationSourceNativeRoleV3(ctx, true)
		case RoutedIntegrityPrepareRoleV3:
			err = RunRoutedIntegrityPrepareRoleV3(ctx)
			if err == nil {
				var report nativeReportV3
				report, err = nativeReportProcessV3("prepare", RoutedLaunchContextV3{})
				if err == nil {
					err = nativeEmitV3(report)
				}
			}
		case nativeSeedRoleV3:
			err = nativeSeedStoreV3(ctx)
		default:
			os.Exit(m.Run())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "native role failed:", os.Args[1], err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type nativeAuthV3 struct {
	Account    adminauth.Account
	Credential string
}
type nativeSeedResultV3 struct {
	Access   [4]recoveryreserve.ReaderAccessV2
	Profiles [3]recoveryreserve.ProfileV2
}
type nativeReportV3 struct {
	Role                                           string `json:"role"`
	PID, UID, GID, PeerPID                         int
	Groups                                         []int
	Caps                                           map[string]string
	Namespace, Epoch, Generation                   uint64
	ReadOnlyDescriptors                            int
	Running, Observed                              string
	FactoryOpened                                  bool
	Integrity, PrivateRoot, IntegrityReady         bool
	FreshScope, RetirementFD, RetirementPathDenied bool
}
type nativeCloseV3 func() error

func (f nativeCloseV3) Close() error { return f() }

func nativeReportProcessV3(role string, c RoutedLaunchContextV3) (nativeReportV3, error) {
	r := nativeReportV3{Integrity: c.Integrity, PrivateRoot: c.IntegrityRoot != nil, Role: role, PID: os.Getpid(), UID: os.Getuid(), GID: os.Getgid(), PeerPID: int(c.PeerPID), Epoch: c.Epoch, Caps: map[string]string{}}
	r.FreshScope = c.FreshScopeEnabled
	if err := nativeRetirementAccessV3(role, c); err != nil {
		return r, err
	}
	r.RetirementFD = c.FreshScope != nil
	r.RetirementPathDenied = c.FreshScopeEnabled
	var err error
	r.Groups, err = os.Getgroups()
	if err != nil {
		return r, err
	}
	r.Namespace, err = namespaceID("/proc/self/ns/net")
	if err != nil {
		return r, err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return r, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (strings.HasPrefix(key, "Cap") || key == "NoNewPrivs") {
			r.Caps[key] = strings.TrimSpace(value)
		}
	}
	return r, nil
}

// This checks descriptor isolation only. The fixture receipt below does not
// attest that any old process or namespace was actually retired.
func nativeRetirementAccessV3(role string, c RoutedLaunchContextV3) error {
	if !c.FreshScopeEnabled {
		if c.FreshScope != nil {
			return errors.New("receipt inherited without fresh-scope opt-in")
		}
		return nil
	}
	path := "/proc/self/fd/5/../" + nativeRetirementFileV3
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	file, openErr := os.Open(path)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(openErr, os.ErrPermission) {
		return errors.New("root receipt reopen was not denied")
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		return errors.New("root receipt path read was not denied")
	}
	if role == "helper" {
		if c.FreshScope == nil || c.FreshScope.Receipt == nil || c.FreshScope.Receipt.Fd() != 14 {
			return errors.New("helper missing inherited receipt FD14")
		}
		pinned, err := c.FreshScope.Receipt.Stat()
		if err != nil || !os.SameFile(info, pinned) {
			return errors.New("helper receipt descriptor differs from root file")
		}
		if _, err := readRetirementFileV3(c.FreshScope.Receipt, c.FreshScope.Binding); err != nil {
			return err
		}
		if _, err := c.FreshScope.Receipt.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EBADF) {
			return errors.New("helper receipt descriptor permitted a write")
		}
		return nil
	}
	if role != "api" || c.FreshScope != nil {
		return errors.New("API received private receipt or binding")
	}
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, file := range files {
		pinned, err := os.Stat("/proc/self/fd/" + file.Name())
		if errors.Is(err, os.ErrNotExist) { // ReadDir's closed descriptor can appear.
			continue
		}
		if err != nil {
			return err
		}
		if os.SameFile(info, pinned) {
			return errors.New("API inherited root receipt descriptor")
		}
	}
	return nil
}
func nativeEmitV3(r nativeReportV3) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_REPORT %s\n", data)
	return err
}

// A grouped runtime must never use a second local engine. Every method fails
// closed and is counted; this is not a simulated local readback.
type nativeForbiddenLocalV3 struct{ calls atomic.Int32 }

func (*nativeForbiddenLocalV3) Name() string { return "grouped-local-denied" }
func (e *nativeForbiddenLocalV3) Validate(configpoc.Config) error {
	e.calls.Add(1)
	return ErrUnavailable
}
func (e *nativeForbiddenLocalV3) Apply(context.Context, configpoc.Revision) error {
	e.calls.Add(1)
	return ErrUnavailable
}
func (e *nativeForbiddenLocalV3) Current() string { e.calls.Add(1); return "" }

func nativeFactoriesV3() RoutedLaunchFactoriesV3 {
	var binding adminauth.SessionBinding
	var sessionToken string
	var launch RoutedLaunchContextV3
	local := &nativeForbiddenLocalV3{}
	return RoutedLaunchFactoriesV3{
		Helper: func(ctx context.Context, c RoutedLaunchContextV3) (out RoutedHelperComponentsV3, err error) {
			identity := networkexecutor.OwnedNamespaceIdentity{UID: c.Identities.HelperUID, GID: c.Identities.IPCGID, Namespace: c.Metadata.GatewayNamespace, Host: c.Metadata.HostNamespace, BootID: c.Metadata.BootID, RunID: c.Metadata.RunID}
			var pools [3]*recoveryreserve.ReadOnlyPoolV2
			defer func() {
				for _, p := range pools {
					if p != nil {
						err = errors.Join(err, p.Close())
					}
				}
			}()
			for i, resource := range []RoutedReaderRootV3{c.Admission, c.Plan, c.Emergency} {
				pools[i], err = recoveryreserve.OpenReadOnlyV2(resource.Root, resource.Access, resource.Profile)
				if err != nil {
					return out, err
				}
			}
			reader, err := configpoc.NewRoutedSelectionReaderV2(c.Store, configpoc.SelectionReaderOptionsV2{Access: c.Access, Identity: identity, Admission: pools[0], Plan: pools[1], Emergency: pools[2], Budget: c.Budget})
			if err != nil {
				return out, err
			}
			view, err := reader.PrepareCurrentView(ctx)
			if err != nil {
				return out, err
			}
			kernel, err := newRoutedKernelV3(c.Metadata)
			if err != nil {
				return out, err
			}
			for _, table := range []routedactivation.Table{routedactivation.LegacyTable, routedactivation.RoutedTable, routedactivation.LocalTable} {
				_, present, err := kernel.Observe(ctx, table)
				if err != nil || present {
					return out, errors.New("native bootstrap requires real table absence")
				}
			}
			network, err := networkexecutor.NewInOwnedNamespaceWithReader(ctx, c.Gateway, c.Host, identity, c.Access.ReaderGID)
			if err != nil {
				return out, err
			}
			defer func() {
				if err != nil {
					_ = network.Close()
				}
			}()
			listeners, err := newRoutedEmptyListenersV3(c.Metadata)
			if err != nil {
				return out, err
			}
			var bindings []networkplan.Binding
			for _, name := range []string{"lan0", "wan0"} {
				link, err := net.InterfaceByName(name)
				if err != nil || link.Flags&net.FlagUp == 0 {
					return out, errors.New("native isolated L2 link is absent or disabled")
				}
				bindings = append(bindings, networkplan.Binding{Name: name, HardwareAddress: link.HardwareAddr.String()})
			}
			authority, err := NewRoutedAuthority(kernel, network, listeners, routedactivation.Options{Legacy: view.Saved.Firewall, Local: &view.Saved.LocalServices, ObservedBindings: bindings}, identity)
			if err != nil {
				return out, err
			}
			out.Cleanup = nativeCloseV3(func() error { return errors.Join(authority.group.Close(), network.Close()) })
			out.Authority = authority
			out.Compatibility, err = NewRoutedReadbackSessionV3(c.Metadata.RunID, c.Metadata.GatewayNamespace, authority)
			if err != nil {
				return out, err
			}
			report, err := nativeReportProcessV3("helper", c)
			if err != nil {
				return out, err
			}
			report.ReadOnlyDescriptors, err = nativeReadOnlyPoolsV3()
			if err != nil {
				return out, err
			}
			if _, err := c.Access.ReadOwnedFile(ctx, c.Store, "selected.json", 4096); !errors.Is(err, recoveryreserve.ErrInvalid) {
				return out, errors.New("helper acquired owner-only read entry")
			}
			writer, writeErr := os.OpenFile("/proc/self/fd/5/checkpoint.lock", os.O_WRONLY, 0)
			if writer != nil {
				_ = writer.Close()
			}
			if !errors.Is(writeErr, os.ErrPermission) {
				return out, errors.New("helper writer lock permission not denied")
			}
			if _, err := os.ReadFile("/proc/self/fd/5/../api-auth.json"); !errors.Is(err, os.ErrPermission) {
				return out, errors.New("helper credential access not denied")
			}
			err = nativeEmitV3(report)
			return out, err
		},
		API: func(ctx context.Context, c RoutedLaunchContextV3) (out OperationsRuntimeOptionsV2, cleanup io.Closer, err error) {
			if err := nativeRetirementAccessV3("api", c); err != nil {
				return out, nil, err
			}
			step := "api-read-auth"
			defer func() {
				if err != nil {
					err = fmt.Errorf("native fixture %s: %w", step, err)
				}
			}()
			if c.Integrity {
				if c.IntegrityRoot != nil {
					return out, nil, errors.New("API inherited private integrity root")
				}
				if _, e := os.ReadFile("/proc/self/fd/5/../integrity/integrity-fence"); !errors.Is(e, os.ErrPermission) {
					return out, nil, errors.New("API private marker access not denied")
				}
				files, e := os.ReadDir("/proc/self/fd")
				if e != nil {
					return out, nil, e
				}
				for _, file := range files {
					path, e := os.Readlink("/proc/self/fd/" + file.Name())
					if e == nil && (strings.HasSuffix(path, "/integrity") || strings.Contains(path, "/integrity/")) {
						return out, nil, errors.New("API inherited private integrity descriptor")
					}
				}
			}
			launch = c
			if _, err := c.Access.ReadFile(ctx, c.Store, "selected.json", 4096); !errors.Is(err, recoveryreserve.ErrInvalid) {
				return out, nil, errors.New("API unexpectedly acquired helper reader identity")
			}
			var auth nativeAuthV3
			data, err := os.ReadFile("/proc/self/fd/5/../api-auth.json")
			if err != nil {
				return out, nil, err
			}
			if err = json.Unmarshal(data, &auth); err != nil {
				return out, nil, err
			}
			step = "api-open-audit"
			audit, err := os.OpenFile("/proc/self/fd/5/../api-audit.jsonl", os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return out, nil, err
			}
			var pools [3]*recoveryreserve.PoolV2
			cleanup = nativeCloseV3(func() error {
				result := audit.Close()
				for _, p := range pools {
					if p != nil {
						result = errors.Join(result, p.Close())
					}
				}
				if local.calls.Load() != 0 {
					result = errors.Join(result, errors.New("grouped runtime invoked forbidden local engine"))
				}
				return result
			})
			step = "api-create-auth-manager"
			manager, err := adminauth.New([]adminauth.Account{auth.Account}, func(e adminauth.Event) error { return json.NewEncoder(audit).Encode(e) })
			if err != nil {
				return out, cleanup, err
			}
			step = "api-authenticate"
			_, token, err := manager.Login(auth.Account.Username, auth.Credential)
			if err != nil {
				return out, cleanup, err
			}
			binding, err = manager.ResolveSession(token)
			if err != nil {
				return out, cleanup, err
			}
			sessionToken = token
			for i, resource := range []RoutedReaderRootV3{c.Admission, c.Plan, c.Emergency} {
				step = []string{"api-open-admission", "api-open-plan", "api-open-emergency"}[i]
				pools[i], err = recoveryreserve.OpenSharedV2(resource.Root, resource.Access)
				if err != nil {
					return out, cleanup, err
				}
			}
			out = OperationsRuntimeOptionsV2{RoutedFreshScope: c.FreshScopeEnabled, Store: c.Store, Budget: nativeBudgetV3(), Auth: manager, Local: []configpoc.Engine{local}, Origin: "https://127.0.0.1:9443", Runtime: configpoc.RuntimeOptionsV2{SharedReader: &c.Access, GuardDeadlines: true, BootID: c.Metadata.BootID, Pools: configpoc.RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}}}
			fmt.Fprintln(os.Stderr, "ANDEIVA_NATIVE_STEP api-options-prepared")
			return out, cleanup, nil
		},
		ServeAPI: func(ctx context.Context, r *RoutedOperationsRuntimeV3, ready func() error) (result error) {
			step := "api-current"
			fmt.Fprintln(os.Stderr, "ANDEIVA_NATIVE_STEP api-runtime-opened")
			defer func() {
				if result != nil {
					result = fmt.Errorf("native fixture %s: %w", step, result)
				}
			}()
			current, err := r.Service.Current(binding, "routed")
			if err != nil {
				return err
			}
			step = "api-routed-observe"
			observed, err := r.routed.Call(ctx, "observe", struct{}{})
			if err != nil {
				return err
			}
			if current.Routed == nil || current.Global.Running == "" || current.Global.Running != observed.Observed.Revision || observed.Observed.Receipt.Phase != "idle" || local.calls.Load() != 0 {
				return errors.New("factory opened without verified grouped readback")
			}
			step = "api-https-readback"
			server := httptest.NewUnstartedServer(r.Handler)
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			transport, ok := client.Transport.(*http.Transport)
			if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == nil {
				return errors.New("native HTTPS client lacks certificate verification")
			}
			for _, authenticated := range []bool{false, true} {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v2/config/current", nil)
				if err != nil {
					return err
				}
				request.Host = "127.0.0.1:9443"
				request.Header.Set("Origin", "https://127.0.0.1:9443")
				if authenticated {
					request.Header.Set("Authorization", "Bearer "+sessionToken)
				}
				response, err := client.Do(request)
				if err != nil {
					return err
				}
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 256<<10))
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					return errors.Join(readErr, closeErr)
				}
				if !authenticated {
					if response.StatusCode != 401 {
						return errors.New("native HTTPS allowed anonymous configuration read")
					}
					continue
				}
				var wire struct {
					Current struct {
						Global struct {
							Running string `json:"running_revision"`
						} `json:"global"`
					} `json:"current"`
				}
				if response.StatusCode != 200 || json.Unmarshal(body, &wire) != nil || wire.Current.Global.Running != current.Global.Running {
					return errors.New("authenticated native HTTPS readback differs")
				}
			}
			report, err := nativeReportProcessV3("api", launch)
			if err != nil {
				return err
			}
			report.IntegrityReady = r.Service.RuntimeIntegrityReadyV1()
			if launch.Integrity && !report.IntegrityReady {
				return errors.New("native API not integrity qualified")
			}
			report.FactoryOpened = true
			report.Generation = current.Global.Generation
			report.Running = current.Global.Running
			report.Observed = observed.Observed.Revision
			if err = nativeEmitV3(report); err != nil {
				return err
			}
			step = "api-publish-ready"
			if err = ready(); err != nil {
				return err
			}
			<-ctx.Done()
			if local.calls.Load() != 0 {
				return errors.New("forbidden local engine invoked")
			}
			return nil
		},
	}
}

func nativeReadOnlyPoolsV3() (int, error) {
	var roots []string
	for fd := 6; fd <= 8; fd++ {
		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return 0, err
		}
		roots = append(roots, path+"/")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		path, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			continue
		}
		for _, root := range roots {
			if strings.HasPrefix(path, root) {
				fd, err := strconv.Atoi(entry.Name())
				if err != nil {
					return 0, err
				}
				flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
					return 0, errors.New("writable helper pool descriptor")
				}
				count++
			}
		}
	}
	if count < 3 {
		return count, errors.New("no read-only pool descriptors observed")
	}
	return count, nil
}

func nativeBudgetV3() configpoc.BudgetV2 { return configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20} }
func nativeSelectionBudgetV3() configpoc.SelectionReadBudgetV2 {
	return configpoc.SelectionReadBudgetV2{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128}
}

type nativeLogV3 struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *nativeLogV3) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(p) > 65536 {
		return 0, errors.New("native report limit")
	}
	return b.buffer.Write(p)
}
func (b *nativeLogV3) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }

func TestNativeRoutedLaunchV3(t *testing.T)          { testNativeRoutedLaunchV3(t, false, false) }
func TestNativeRoutedIntegrityLaunchV3(t *testing.T) { testNativeRoutedLaunchV3(t, true, false) }
func TestNativeRoutedIntegrityFreshScopeLaunchV3(t *testing.T) {
	testNativeRoutedLaunchV3(t, true, true)
}
func testNativeRoutedLaunchV3(t *testing.T, integrity, freshScope bool) {
	if os.Getenv("ANDEIVA_NATIVE_LAUNCH_V3") != "1" {
		t.Skip("requires authorized isolated root laboratory harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root laboratory only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	self, e := os.Executable()
	if e != nil || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("untrusted native fixture binary")
	}
	var namespaces [3]*os.File
	for i := range namespaces {
		fd := i + 3
		var fs unix.Statfs_t
		kind, e := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if e != nil || kind != unix.CLONE_NEWNET || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
			t.Fatal("invalid inherited namespace")
		}
		namespaces[i] = os.NewFile(uintptr(fd), "native-netns")
		unix.CloseOnExec(fd)
		defer namespaces[i].Close()
	}
	host, e := os.Open("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	defer host.Close()
	base, e := os.MkdirTemp(filepath.Dir(self), "state-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error("native resource cleanup", err)
		}
	}()
	if e = os.Chmod(base, 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"store", "admission", "plan", "emergency"} {
		path := filepath.Join(base, name)
		if e = os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.APIUID), nativeReaderGIDV3); e != nil {
			t.Fatal(e)
		}
	}
	sockets := filepath.Join(base, "sockets")
	if e = os.Mkdir(sockets, 0750); e != nil {
		t.Fatal(e)
	}
	// The production manager applies the exact directory mode after creation;
	// the fixture must also work under the service's restrictive UMask0077.
	if e = os.Chmod(sockets, 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(sockets, int(nativeIdentitiesV3.HelperUID), int(nativeIdentitiesV3.IPCGID)); e != nil {
		t.Fatal(e)
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		t.Fatal(e)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	subject, e := configpoc.NewSubjectIDV2()
	if e != nil {
		t.Fatal(e)
	}
	auth := nativeAuthV3{Account: adminauth.Account{Username: "native-operator", Role: "admin", SubjectID: subject, CredentialRevision: hex.EncodeToString(digest[:]), CredentialSHA256: hex.EncodeToString(digest[:])}, Credential: credential}
	data, e := json.Marshal(auth)
	if e != nil {
		t.Fatal(e)
	}
	for name, content := range map[string][]byte{"api-auth.json": data, "api-audit.jsonl": nil, "seed-profiles.json": nil} {
		path := filepath.Join(base, name)
		if e = os.WriteFile(path, content, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.APIUID), int(nativeIdentitiesV3.APIGID)); e != nil {
			t.Fatal(e)
		}
	}
	baseFD, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	seed := exec.CommandContext(ctx, "/usr/bin/setpriv", "--reuid=62001", "--regid=62001", "--groups=62004", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, nativeSeedRoleV3)
	seed.ExtraFiles = []*os.File{baseFD}
	seed.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	seed.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	output, e := seed.CombinedOutput()
	runtime.UnlockOSThread()
	_ = baseFD.Close()
	if e != nil {
		t.Fatalf("offline seed failed: %v %s", e, output)
	}
	data, e = os.ReadFile(filepath.Join(base, "seed-profiles.json"))
	if e != nil {
		t.Fatal(e)
	}
	var prepared nativeSeedResultV3
	if e = json.Unmarshal(data, &prepared); e != nil {
		t.Fatal(e)
	}
	var roots [4]*os.Root
	for i, name := range []string{"store", "admission", "plan", "emergency"} {
		roots[i], e = os.OpenRoot(filepath.Join(base, name))
		if e != nil {
			t.Fatal(e)
		}
		defer roots[i].Close()
	}
	directory, e := os.OpenRoot(sockets)
	if e != nil {
		t.Fatal(e)
	}
	defer directory.Close()
	inode := func(f *os.File) uint64 {
		info, e := f.Stat()
		if e != nil {
			t.Fatal(e)
		}
		return info.Sys().(*syscall.Stat_t).Ino
	}
	bootBytes, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	boot, e := canonicalBoot(bootBytes)
	if e != nil {
		t.Fatal(e)
	}
	var run [16]byte
	if _, e = rand.Read(run[:]); e != nil {
		t.Fatal(e)
	}
	metadata := Metadata{SchemaVersion: 1, RunID: hex.EncodeToString(run[:]), BootID: boot, HostNamespace: inode(host), GatewayNamespace: inode(namespaces[0]), SourceNamespace: inode(namespaces[1]), SinkNamespace: inode(namespaces[2])}
	resource := func(i int) RoutedReaderRootV3 {
		v := RoutedReaderRootV3{Root: roots[i], Access: prepared.Access[i]}
		if i > 0 {
			v.Profile = prepared.Profiles[i-1]
		}
		return v
	}
	var logs nativeLogV3
	var private *os.Root
	if integrity {
		path := filepath.Join(base, "integrity")
		if e = os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.HelperUID), int(nativeIdentitiesV3.IPCGID)); e != nil {
			t.Fatal(e)
		}
		private, e = os.OpenRoot(path)
		if e != nil {
			t.Fatal(e)
		}
		defer private.Close()
		if e = PrepareRoutedIntegrityLaunchV3(ctx, nativeIdentitiesV3, private, &logs); e != nil {
			t.Fatalf("explicit capless preparation failed: %v %s", e, logs.String())
		}
		original, e := private.ReadFile(routedIntegrityFenceNameV3)
		if e != nil || len(original) != 4096 || original[routedIntegrityFenceStateV3] != 0 {
			t.Fatal("invalid prepared marker", e)
		}
		if e = PrepareRoutedIntegrityLaunchV3(ctx, nativeIdentitiesV3, private, io.Discard); e == nil {
			t.Fatal("installer reset an existing marker")
		}
		after, e := private.ReadFile(routedIntegrityFenceNameV3)
		if e != nil || !bytes.Equal(original, after) {
			t.Fatal("failed preparation changed marker", e)
		}
	}
	var retirement *RoutedFreshScopeOptionsV3
	if freshScope {
		retirement = nativeRetirementReceiptV3(t, base, metadata)
		defer retirement.Receipt.Close()
	}
	supervisor, e := StartRoutedLaunchV3(ctx, RoutedLaunchResourcesV3{FreshScope: retirement, Metadata: metadata, Identities: nativeIdentitiesV3, Gateway: namespaces[0], Host: host, Directory: directory, IntegrityRoot: private, Store: resource(0), Admission: resource(1), Plan: resource(2), Emergency: resource(3), Budget: nativeSelectionBudgetV3()}, &logs)
	if e != nil {
		t.Fatalf("native launch failed: %v\n%s", e, logs.String())
	}
	defer supervisor.Close()
	helper, api := supervisor.PIDs()
	if helper <= 1 || api <= 1 || helper == api {
		t.Fatal("invalid native processes")
	}
	if e = supervisor.RestartAPI(ctx); e != nil {
		t.Fatalf("native restart failed: %v\n%s", e, logs.String())
	}
	h2, a2 := supervisor.PIDs()
	if helper != h2 || api == a2 {
		t.Fatal("restart replaced helper or retained API PID")
	}
	if e = supervisor.Close(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(logs.String(), "native role failed:") {
		t.Fatalf("child cleanup failed: %s", logs.String())
	}
	var helpers, apis, preparers int
	var previous nativeReportV3
	for _, line := range strings.Split(logs.String(), "\n") {
		if !strings.HasPrefix(line, "ANDEIVA_NATIVE_REPORT ") {
			continue
		}
		var r nativeReportV3
		if e = json.Unmarshal([]byte(strings.TrimPrefix(line, "ANDEIVA_NATIVE_REPORT ")), &r); e != nil {
			t.Fatal(e)
		}
		wantCap := "0000000000000000"
		if r.Role == "prepare" {
			preparers++
			if !integrity || r.UID != 62002 || r.GID != 62003 || len(r.Groups) != 0 || r.Namespace != metadata.HostNamespace {
				t.Fatal("preparer identity/capless namespace mismatch", r)
			}
		} else if r.Role == "helper" {
			if r.FreshScope != freshScope || r.RetirementFD != freshScope || r.RetirementPathDenied != freshScope {
				t.Fatal("helper retirement descriptor/profile mismatch", r)
			}
			if r.Integrity != integrity || r.PrivateRoot != integrity {
				t.Fatal("helper integrity profile mismatch", r)
			}
			helpers++
			wantCap = "0000000000001000"
			if r.PID != helper || r.UID != 62002 || r.GID != 62003 || r.Namespace != metadata.GatewayNamespace || r.ReadOnlyDescriptors < 3 {
				t.Fatal("helper profile mismatch", r)
			}
			if len(r.Groups) != 1 || r.Groups[0] != nativeReaderGIDV3 {
				t.Fatal("helper groups differ", r.Groups)
			}
		} else if r.Role == "api" {
			if r.FreshScope != freshScope || r.RetirementFD || r.RetirementPathDenied != freshScope {
				t.Fatal("API received retirement authority or wrong capability", r)
			}
			if r.Integrity != integrity || r.PrivateRoot || (integrity && !r.IntegrityReady) {
				t.Fatal("API integrity/root/readiness mismatch", r)
			}
			apis++
			if r.UID != 62001 || r.GID != 62001 || r.Namespace != metadata.HostNamespace || r.PeerPID != helper || !r.FactoryOpened || r.Running == "" || r.Running != r.Observed || r.Epoch != uint64(apis) {
				t.Fatal("API profile/readback mismatch", r)
			}
			if len(r.Groups) != 1 || r.Groups[0] != 62003 {
				t.Fatal("API groups differ", r.Groups)
			}
			if apis == 2 && (r.Generation < previous.Generation || r.Running != previous.Running) {
				t.Fatal("restart lost verified configuration")
			}
			previous = r
		} else {
			t.Fatal("unexpected native role")
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if r.Caps[key] != wantCap {
				t.Fatal("capability mismatch", r.Role, key, r.Caps[key])
			}
		}
		if r.Caps["NoNewPrivs"] != "1" {
			t.Fatal("NNP missing")
		}
	}
	if (integrity && preparers != 1) || (!integrity && preparers != 0) {
		t.Fatal("incomplete preparation report", preparers)
	}
	if helpers != 1 || apis != 2 {
		t.Fatalf("incomplete native reports %d/%d: %s", helpers, apis, logs.String())
	}
	t.Log("real helper/API identities, native table absence, grouped boot/readback and retained-helper API restart passed; no traffic or descendant cleanup qualification")
	if freshScope {
		t.Log("root receipt FD14 readable only by helper; API receipt inheritance, reopening and reading denied before and after API restart; fictitious old identity, no retirement/recovery qualification")
	}
}

func nativeRetirementReceiptV3(t *testing.T, base string, m Metadata) *RoutedFreshScopeOptionsV3 {
	t.Helper()
	identity := networkexecutor.OwnedNamespaceIdentity{UID: nativeIdentitiesV3.HelperUID, GID: nativeIdentitiesV3.IPCGID, Namespace: m.GatewayNamespace, Host: m.HostNamespace, BootID: m.BootID, RunID: m.RunID}
	// Deliberately fictitious old scope: this test exercises FD ownership only.
	old := identity
	old.Namespace = 1
	for old.Namespace == identity.Namespace || old.Namespace == identity.Host {
		old.Namespace++
	}
	old.RunID = strings.Repeat("a", 32)
	if old.RunID == identity.RunID {
		old.RunID = strings.Repeat("b", 32)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeRootRetirementReceiptV3(RootRetirementReceiptV3{Version: 3, Old: old, MetadataSHA256: strings.Repeat("a", 64), DrainedAtBootNS: now.Nano()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, nativeRetirementFileV3)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if err = file.Chown(0, 0); err != nil {
		t.Fatal(err)
	}
	if err = file.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	binding := RoutedFreshScopeBindingV3{ReceiptSHA256: retirementDigestV3(raw), NewIdentity: identity}
	if _, err = readRetirementFileV3(reader, binding); err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	return &RoutedFreshScopeOptionsV3{Receipt: reader, Binding: binding}
}

// The trusted offline preparer is supplied by the configuration module; it
// must never assert that declared configuration is already effective.
func nativeSeedStoreV3(ctx context.Context) error {
	if os.Getuid() != 62001 || os.Geteuid() != 62001 || os.Getgid() != 62001 || os.Getegid() != 62001 {
		return ErrIdentity
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || privilegeFields(string(status), false) != nil {
		return ErrIdentity
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 1 || groups[0] != nativeReaderGIDV3 {
		return ErrIdentity
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(3, unix.F_GETFL, 0)
	if err != nil || unix.Fstat(3, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return ErrIdentity
	}
	unix.CloseOnExec(3)
	parent, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", os.Getppid()))
	if err != nil || !rootRoutedParentStatusV3(parent, os.Getppid()) {
		return ErrIdentity
	}
	base, err := os.OpenRoot("/proc/self/fd/3")
	if err != nil {
		return err
	}
	defer base.Close()
	var auth nativeAuthV3
	data, err := base.ReadFile("api-auth.json")
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &auth); err != nil {
		return err
	}
	var roots [4]*os.Root
	for i, name := range []string{"store", "admission", "plan", "emergency"} {
		roots[i], err = base.OpenRoot(name)
		if err != nil {
			return err
		}
		defer roots[i].Close()
	}
	var pools [3]*recoveryreserve.PoolV2
	defer func() {
		for _, p := range pools {
			if p != nil {
				_ = p.Close()
			}
		}
	}()
	roles := []recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2}
	capacities := []int{4096, 16384, 8192}
	var prepared nativeSeedResultV3
	for i := range pools {
		pools[i], err = recoveryreserve.PrepareV2(roots[i+1], 18, capacities[i], roles[i])
		if err != nil {
			return err
		}
		prepared.Profiles[i], err = pools[i].Profile()
		if err != nil {
			return err
		}
	}
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		return err
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}})
	if err != nil {
		return err
	}
	err = configpoc.PrepareOfflineRoutedStoreV3(ctx, roots[0], nativeBudgetV3(), configpoc.RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}, legacy, local, []configpoc.SubjectV2{{ID: auth.Account.SubjectID, Login: auth.Account.Username, CredentialRevision: auth.Account.CredentialRevision}}, time.Now().UTC())
	if err != nil {
		return err
	}
	for i, p := range pools {
		if err = p.Close(); err != nil {
			return err
		}
		pools[i] = nil
	}
	for i, root := range roots {
		prepared.Access[i], err = nativeShareOfflineV3(root)
		if err != nil {
			return err
		}
	}
	data, err = json.Marshal(prepared)
	if err != nil {
		return err
	}
	result, err := base.OpenFile("seed-profiles.json", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = result.Write(data)
	if err == nil {
		err = result.Sync()
	}
	return errors.Join(err, result.Close())
}

// Only the stopped API-owned fixture writer converts these flat private roots.
func nativeShareOfflineV3(root *os.Root) (recoveryreserve.ReaderAccessV2, error) {
	var access recoveryreserve.ReaderAccessV2
	directory, err := root.Open(".")
	if err != nil {
		return access, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return access, err
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() {
			return access, ErrIdentity
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 62001 || st.Nlink != 1 {
			return access, ErrIdentity
		}
		if err = root.Chown(entry.Name(), -1, nativeReaderGIDV3); err != nil {
			return access, err
		}
		mode := os.FileMode(0640)
		if entry.Name() == "checkpoint.lock" {
			mode = 0600
		}
		if err = root.Chmod(entry.Name(), mode); err != nil {
			return access, err
		}
	}
	if err = directory.Chown(-1, nativeReaderGIDV3); err != nil {
		return access, err
	}
	if err = directory.Chmod(os.ModeSetgid | 0750); err != nil {
		return access, err
	}
	if err = directory.Sync(); err != nil {
		return access, err
	}
	info, err := directory.Stat()
	if err != nil {
		return access, err
	}
	st := info.Sys().(*syscall.Stat_t)
	access = recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: 62001, ReaderGID: nativeReaderGIDV3, Device: st.Dev, Inode: st.Ino}
	return access, access.CheckDirectory(root)
}
