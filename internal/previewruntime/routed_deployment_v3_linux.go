//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

const routedDeploymentPathV3 = "/etc/andeiva-preview/grouped.json"
const routedDeploymentDataV3 = DataDir + "/grouped"
const routedDeploymentRunV3 = RuntimeDir + "/grouped"

type routedAccessRecordV3 struct {
	Version   uint32 `json:"version"`
	OwnerUID  uint32 `json:"owner_uid"`
	ReaderGID uint32 `json:"reader_gid"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
}

func (a routedAccessRecordV3) access() recoveryreserve.ReaderAccessV2 {
	return recoveryreserve.ReaderAccessV2{Version: a.Version, OwnerUID: a.OwnerUID, ReaderGID: a.ReaderGID, Device: a.Device, Inode: a.Inode}
}

type routedProfileRecordV3 struct {
	ID       string                 `json:"id"`
	Role     recoveryreserve.RoleV2 `json:"role"`
	Slots    int                    `json:"slots"`
	Capacity int                    `json:"capacity"`
}

func (p routedProfileRecordV3) profile() recoveryreserve.ProfileV2 {
	return recoveryreserve.ProfileV2{ID: p.ID, Role: p.Role, Slots: p.Slots, Capacity: p.Capacity}
}

type routedWriteBudgetV3 struct {
	Bytes  uint64 `json:"bytes"`
	Inodes uint64 `json:"inodes"`
}
type routedReadBudgetV3 struct {
	Entries     uint64 `json:"entries"`
	Objects     uint64 `json:"objects"`
	Edges       uint64 `json:"edges"`
	IOCalls     uint64 `json:"io_calls"`
	Bytes       uint64 `json:"bytes"`
	ActiveBytes uint64 `json:"active_bytes"`
	Depth       int    `json:"depth"`
}

func (b routedReadBudgetV3) budget() configpoc.SelectionReadBudgetV2 {
	return configpoc.SelectionReadBudgetV2{Entries: b.Entries, Objects: b.Objects, Edges: b.Edges, IOCalls: b.IOCalls, Bytes: b.Bytes, ActiveBytes: b.ActiveBytes, Depth: b.Depth}
}

type routedDeploymentRecordV3 struct {
	LocalOrigin      *RoutedLocalOriginV3    `json:"local_origin"`
	Version          int                     `json:"version"`
	NamespaceProfile string                  `json:"namespace_profile"`
	Identities       Identities              `json:"identities"`
	AccountsSHA256   string                  `json:"accounts_sha256"`
	Access           []routedAccessRecordV3  `json:"access"`
	Profiles         []routedProfileRecordV3 `json:"profiles"`
	WriteBudget      routedWriteBudgetV3     `json:"write_budget"`
	ReadBudget       routedReadBudgetV3      `json:"read_budget"`
}

// The deployment record pins resources, not selected policy or permission to
// apply it. Independent helper readers must still validate every authority edge.
func decodeRoutedDeploymentV3(data []byte, ids Identities) (routedDeploymentRecordV3, error) {
	var record routedDeploymentRecordV3
	if len(data) == 0 || len(data) > 16384 || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &record) != nil || record.Version != 1 || validateRoutedLocalOriginV3(record.LocalOrigin) != nil || record.NamespaceProfile != "host-gateway-v2" || len(record.Access) != 4 || len(record.Profiles) != 3 || ids.Validate() != nil || record.Identities != ids || !validHex(record.AccountsSHA256, 32) || record.WriteBudget.Bytes == 0 || record.WriteBudget.Inodes == 0 {
		return record, ErrConfiguration
	}
	b := record.ReadBudget
	if b.Entries == 0 || b.Objects == 0 || b.Edges == 0 || b.IOCalls == 0 || b.Bytes == 0 || b.ActiveBytes == 0 || b.Depth <= 0 {
		return record, ErrConfiguration
	}
	seen := map[[2]uint64]bool{}
	reader := record.Access[0].ReaderGID
	for _, a := range record.Access {
		key := [2]uint64{a.Device, a.Inode}
		if a.Version != 1 || a.OwnerUID != ids.APIUID || reader == 0 || a.ReaderGID != reader || reader == ids.APIGID || reader == ids.IPCGID || a.Inode == 0 || seen[key] {
			return record, ErrIdentity
		}
		seen[key] = true
	}
	profileIDs := map[string]bool{}
	roles := [3]recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2}
	capacities := [3]int{4096, 16384, 8192}
	for i, p := range record.Profiles {
		if !validHex(p.ID, 16) || profileIDs[p.ID] || p.Role != roles[i] || p.Slots != 18 || p.Capacity != capacities[i] {
			return record, ErrIdentity
		}
		profileIDs[p.ID] = true
	}
	return record, nil
}

type routedDeploymentResourcesV3 struct {
	launch   RoutedLaunchResourcesV3
	roots    []*os.Root
	files    []*os.File
	listener net.Listener
}

func (r *routedDeploymentResourcesV3) Close() error {
	if r == nil {
		return nil
	}
	var result error
	for _, root := range r.roots {
		result = errors.Join(result, root.Close())
	}
	r.roots = nil
	for _, file := range r.files {
		result = errors.Join(result, file.Close())
	}
	r.files = nil
	if r.listener != nil {
		result = errors.Join(result, r.listener.Close())
		r.listener = nil
	}
	return result
}

func openRoutedDeploymentV3(ctx context.Context, c Config) (resources *routedDeploymentResourcesV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return nil, ErrIdentity
	}
	for _, path := range []string{routedDeploymentDataV3, routedDeploymentRunV3} {
		if ownedDirectory(path, 0, 0, 0755) != nil {
			return nil, ErrIdentity
		}
		dir, e := os.Open(path) // #nosec G304 -- iteration contains only the two fixed deployment directories above.
		if e != nil {
			return nil, ErrIdentity
		}
		clean := fenceNoACLV3(dir, true)
		closeErr := dir.Close()
		if !clean || closeErr != nil {
			return nil, ErrIdentity
		}
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		return nil, err
	}
	if ownedDirectory(routedDeploymentRunV3+"/api", ids.APIUID, ids.APIGID, 0700) != nil {
		return nil, ErrIdentity
	}
	data, err := readOwned(routedDeploymentPathV3, 0, 0, 0600, 16384)
	if err != nil {
		return nil, err
	}
	record, err := decodeRoutedDeploymentV3(data, ids)
	if err != nil {
		return nil, err
	}
	accounts, err := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(accounts)
	if hex.EncodeToString(digest[:]) != record.AccountsSHA256 {
		return nil, ErrIdentity
	}
	m, err := readRoutedMetadataV3()
	if err != nil {
		return nil, err
	}
	r := &routedDeploymentResourcesV3{}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.Close())
		}
	}()
	r.launch = RoutedLaunchResourcesV3{LocalOrigin: cloneRoutedLocalOriginV3(record.LocalOrigin), Metadata: m, Identities: ids, Budget: record.ReadBudget.budget(), StoreBudget: configpoc.BudgetV2{Bytes: record.WriteBudget.Bytes, Inodes: record.WriteBudget.Inodes}}
	gateway, err := openRoutedNamespacePinV3(filepath.Join(routedDeploymentRunV3, "netns", "gateway"), m.GatewayNamespace)
	if err != nil {
		return nil, err
	}
	r.files = append(r.files, gateway)
	r.launch.Gateway = gateway
	host, err := openRoutedNamespacePinV3("/proc/self/ns/net", m.HostNamespace)
	if err != nil {
		return nil, err
	}
	r.files = append(r.files, host)
	r.launch.Host = host
	openRoot := func(path string) (*os.Root, error) {
		if safeParents(path) != nil {
			return nil, ErrStorage
		}
		before, e := os.Lstat(path)
		if e != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, ErrStorage
		}
		root, e := os.OpenRoot(path)
		if e != nil {
			return nil, ErrStorage
		}
		r.roots = append(r.roots, root)
		after, e := root.Stat(".")
		if e != nil || !os.SameFile(before, after) {
			return nil, ErrIdentity
		}
		return root, nil
	}
	roots := [4]*os.Root{}
	for i, name := range []string{"state", "admission", "plan", "emergency"} {
		roots[i], err = openRoot(filepath.Join(routedDeploymentDataV3, name))
		if err != nil {
			return nil, err
		}
		if err = record.Access[i].access().CheckDirectory(roots[i]); err != nil {
			return nil, ErrIdentity
		}
		if i == 0 {
			if old, e := os.Stat(DataDir + "/state"); e == nil {
				current, e := roots[i].Stat(".")
				if e != nil || os.SameFile(old, current) {
					return nil, ErrIdentity
				}
			} else if !os.IsNotExist(e) {
				return nil, ErrStorage
			}
		}
	}
	resource := func(i int) RoutedReaderRootV3 {
		value := RoutedReaderRootV3{Root: roots[i], Access: record.Access[i].access()}
		if i > 0 {
			value.Profile = record.Profiles[i-1].profile()
		}
		return value
	}
	r.launch.Store, r.launch.Admission, r.launch.Plan, r.launch.Emergency = resource(0), resource(1), resource(2), resource(3)
	r.launch.Directory, err = openRoot(filepath.Join(routedDeploymentRunV3, "ipc"))
	if err != nil {
		return nil, err
	}
	r.launch.IntegrityRoot, err = openRoot(filepath.Join(routedDeploymentDataV3, "integrity"))
	if err != nil {
		return nil, err
	}
	if validateRoutedLaunchV3(r.launch) != nil {
		return nil, ErrIdentity
	}
	r.listener, err = inheritedListener(c)
	if err != nil {
		return nil, err
	}
	tcp, ok := r.listener.(*net.TCPListener)
	if !ok {
		return nil, ErrIdentity
	}
	r.launch.Management, err = tcp.File()
	if err != nil {
		return nil, ErrIdentity
	}
	r.files = append(r.files, r.launch.Management)
	if validateRoutedManagementV3(r.launch.Management, c) != nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	return r, nil
}

func readRoutedMetadataV3() (Metadata, error) {
	var m Metadata
	data, err := readOwned(filepath.Join(routedDeploymentRunV3, "runtime.json"), 0, 0, 0644, 8192)
	if err != nil {
		return m, err
	}
	if !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &m) != nil || m.ValidateRouted() != nil || m.SchemaVersion != RoutedMetadataSchemaVersion {
		return m, ErrIdentity
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return m, ErrIdentity
	}
	actual, err := canonicalBoot(boot)
	if err != nil || actual != m.BootID {
		return m, ErrIdentity
	}
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil || host != m.HostNamespace {
		return m, ErrIdentity
	}
	// The original deployment is retained for rollback. Its namespaces are never
	// silently reinterpreted as the new empty grouped baseline.
	if _, err := os.Lstat(RuntimeDir + "/runtime.json"); err == nil {
		old, e := ReadMetadata()
		if e != nil {
			return m, e
		}
		if old.RunID == m.RunID {
			return m, ErrIdentity
		}
		for _, current := range []uint64{m.GatewayNamespace} {
			for _, previous := range []uint64{old.GatewayNamespace, old.SourceNamespace, old.SinkNamespace} {
				if current == previous {
					return m, ErrIdentity
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return m, ErrStorage
	}
	return m, nil
}

func openRoutedNamespacePinV3(path string, expected uint64) (*os.File, error) {
	if expected == 0 || (path != "/proc/self/ns/net" && path != routedDeploymentRunV3+"/netns/gateway") || (path != "/proc/self/ns/net" && safeParents(path) != nil) {
		return nil, ErrIdentity
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if path != "/proc/self/ns/net" {
		flags |= syscall.O_NOFOLLOW
	}
	file, err := os.OpenFile(path, flags, 0) // #nosec G304 -- exact fixed allowlist above; NSFS type/inode is checked before use.
	if err != nil {
		return nil, ErrIdentity
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), unix.NS_GET_NSTYPE, 0)
	if unix.Fstat(int(file.Fd()), &st) != nil || unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC || errno != 0 || kind != unix.CLONE_NEWNET || st.Ino != expected {
		_ = file.Close()
		return nil, ErrIdentity
	}
	return file, nil
}

// RunRoutedSupervisorV3 consumes only an explicitly prepared deployment and
// root-manager namespace pins. It creates no namespace or policy itself.
func RunRoutedSupervisorV3(ctx context.Context, c Config) (result error) {
	resources, err := openRoutedDeploymentV3(ctx, c)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, resources.Close()) }()
	supervisor, err := StartRoutedLaunchV3(ctx, resources.launch, os.Stderr)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, supervisor.Close()) }()
	return keepRoutedSupervisorV3(ctx, supervisor.Done(), supervisor.apiExitV3, supervisor.RestartAPI, os.Stderr)
}

func (s *RoutedLaunchSupervisorV3) apiExitV3() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.api == nil {
		return nil
	}
	return s.api.done
}

// Management failure is not a reason to terminate the independent helper. A
// failed recovery or exhausted retry budget leaves this root process alive,
// preserving PDEATHSIG ownership and the helper's original guardian deadline.
func keepRoutedSupervisorV3(ctx context.Context, helperDone <-chan struct{}, apiExit func() <-chan struct{}, restart func(context.Context) error, diagnostic io.Writer) error {
	var window time.Time
	attempts := 0
	degraded := false
	for {
		var apiDone <-chan struct{}
		if !degraded {
			apiDone = apiExit()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-helperDone:
			return ErrUnavailable
		case <-apiDone:
		}
		now := time.Now()
		if window.IsZero() || now.Sub(window) >= time.Minute {
			window = now
			attempts = 0
		}
		if attempts >= 3 {
			degraded = true
			_, _ = io.WriteString(diagnostic, "ANDEIVA_GROUPED_API_RECOVERY_REQUIRED\n")
			continue
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-helperDone:
			timer.Stop()
			return ErrUnavailable
		case <-timer.C:
		}
		attempts++
		if err := restart(ctx); err != nil {
			degraded = true
			_, _ = io.WriteString(diagnostic, "ANDEIVA_GROUPED_API_RECOVERY_REQUIRED\n")
		}
	}
}
