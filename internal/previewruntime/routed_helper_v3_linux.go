//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// RoutedReaderRootV3 is pinned by the supervisor. None of these resources is
// decoded from a request; the helper borrows roots and opens only read handles.
type RoutedReaderRootV3 struct {
	Root    *os.Root
	Access  recoveryreserve.ReaderAccessV2
	Profile recoveryreserve.ProfileV2
}
type RoutedHelperOptionsV3 struct {
	IntegrityRoot              *os.Root // Explicit trusted resource; nil preserves full-reader profile.
	Store                      *os.Root
	Access                     recoveryreserve.ReaderAccessV2
	Admission, Plan, Emergency RoutedReaderRootV3
	Budget                     configpoc.SelectionReadBudgetV2
	Authority                  configpoc.RoutedAuthorityV1
}

type RoutedHelperRuntimeV3 struct {
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	session    *RoutedSessionV3
	pools      [3]*recoveryreserve.ReadOnlyPoolV2
	metadata   Metadata
	identities Identities
	closed     bool
	fence      *routedIntegrityFenceV3
}

func routedHelperReadinessV3(m Metadata, ids Identities, o RoutedHelperOptionsV3) error {
	if m.ValidateRouted() != nil || ids.Validate() != nil || o.Authority == nil || o.Store == nil || o.Access.Version != 1 || o.Access.OwnerUID != ids.APIUID || o.Access.ReaderGID == 0 || o.Access.ReaderGID == ids.APIGID || o.Access.CheckDirectory(o.Store) != nil {
		return ErrIdentity
	}
	expected := networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: m.GatewayNamespace, Host: m.HostNamespace, BootID: m.BootID, RunID: m.RunID}
	if o.Authority.Identity() != expected {
		return ErrIdentity
	}
	info, e := o.Store.Stat(".")
	if e != nil {
		return ErrIdentity
	}
	directories := []os.FileInfo{info}
	profiles := map[string]bool{}
	for _, item := range []struct {
		root     RoutedReaderRootV3
		role     recoveryreserve.RoleV2
		capacity int
	}{{o.Admission, recoveryreserve.AdmissionV2, 4096}, {o.Plan, recoveryreserve.PlanV2, 16384}, {o.Emergency, recoveryreserve.EmergencyV2, 8192}} {
		r := item.root
		if r.Root == nil || r.Access.OwnerUID != o.Access.OwnerUID || r.Access.ReaderGID != o.Access.ReaderGID || r.Access.CheckDirectory(r.Root) != nil || r.Profile.ID == "" || profiles[r.Profile.ID] || r.Profile.Role != item.role || r.Profile.Slots != 18 || r.Profile.Capacity != item.capacity {
			return ErrIdentity
		}
		profiles[r.Profile.ID] = true
		actual, e := r.Root.Stat(".")
		if e != nil {
			return ErrIdentity
		}
		for _, previous := range directories {
			if os.SameFile(previous, actual) {
				return ErrIdentity
			}
		}
		directories = append(directories, actual)
	}
	return nil
}

func routedHelperProcessFieldsV3(uid, euid, gid, egid int, groups []int, status string, ids Identities, readerGID uint32) error {
	if ids.Validate() != nil || readerGID == 0 || readerGID == ids.APIGID || !matchesIdentity(uid, ids.HelperUID) || !matchesIdentity(euid, ids.HelperUID) || !matchesIdentity(gid, ids.IPCGID) || !matchesIdentity(egid, ids.IPCGID) || privilegeFields(status, true) != nil {
		return ErrIdentity
	}
	hasReader := matchesIdentity(gid, readerGID)
	for _, group := range groups {
		if !matchesIdentity(group, ids.IPCGID) && !matchesIdentity(group, readerGID) {
			return ErrIdentity
		}
		if matchesIdentity(group, readerGID) {
			hasReader = true
		}
	}
	if !hasReader {
		return ErrIdentity
	}
	return nil
}

// OpenRoutedHelperV3 validates the real process and namespace before opening
// read-only pools. It does not provision resources, start a service or adopt an
// encountered namespace. Authority and root lifetimes remain supervisor-owned.
func OpenRoutedHelperV3(ctx context.Context, m Metadata, ids Identities, o RoutedHelperOptionsV3) (*RoutedHelperRuntimeV3, error) {
	if ctx == nil || ctx.Err() != nil || routedHelperReadinessV3(m, ids, o) != nil {
		return nil, ErrIdentity
	}
	groups, e := os.Getgroups()
	if e != nil {
		return nil, ErrIdentity
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil || len(status) > 65536 || routedHelperProcessFieldsV3(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, string(status), ids, o.Access.ReaderGID) != nil {
		return nil, ErrIdentity
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return nil, ErrIdentity
	}
	actualBoot, e := canonicalBoot(boot)
	if e != nil || actualBoot != m.BootID {
		return nil, ErrIdentity
	}
	actual, e := namespaceID("/proc/self/ns/net")
	if e != nil || actual != m.GatewayNamespace || actual == m.HostNamespace {
		return nil, ErrIdentity
	}
	return assembleRoutedHelperV3(ctx, m, ids, o)
}

func assembleRoutedHelperV3(ctx context.Context, m Metadata, ids Identities, o RoutedHelperOptionsV3) (out *RoutedHelperRuntimeV3, err error) {
	if ctx == nil || ctx.Err() != nil || routedHelperReadinessV3(m, ids, o) != nil {
		return nil, ErrIdentity
	}
	lifetime, cancel := context.WithCancel(ctx)
	result := &RoutedHelperRuntimeV3{ctx: lifetime, cancel: cancel, metadata: m, identities: ids}
	defer func() {
		if err != nil {
			_ = result.Close()
		}
	}()
	for i, resource := range []RoutedReaderRootV3{o.Admission, o.Plan, o.Emergency} {
		result.pools[i], err = recoveryreserve.OpenReadOnlyV2(resource.Root, resource.Access, resource.Profile)
		if err != nil {
			return nil, err
		}
	}
	readerOptions := configpoc.SelectionReaderOptionsV2{Access: o.Access, Identity: o.Authority.Identity(), Admission: result.pools[0], Plan: result.pools[1], Emergency: result.pools[2], Budget: o.Budget}
	full, e := configpoc.NewRoutedSelectionReaderV2(o.Store, readerOptions)
	if e != nil {
		return nil, e
	}
	reader := full
	if o.IntegrityRoot != nil {
		result.fence, e = openRoutedIntegrityFenceV3(o.IntegrityRoot, ids.HelperUID, ids.IPCGID)
		if e != nil {
			return nil, e
		}
		readerOptions.Policy = configpoc.SelectionActionAuthorityV2
		reader, e = configpoc.NewRoutedSelectionReaderV2(o.Store, readerOptions)
	}
	if e != nil {
		return nil, e
	}
	source, e := NewRoutedStoreSourceV3(reader)
	if e != nil {
		return nil, e
	}
	if result.fence != nil {
		result.session, e = NewRoutedIntegritySessionV3(o.Authority, source, full, result.fence)
	} else {
		result.session, e = NewRoutedSessionV3(o.Authority, source)
	}
	if e != nil {
		return nil, e
	}
	return result, nil
}

// Serve consumes only an authenticated inherited channel. Controller disconnect
// closes that channel; it neither closes this runtime nor cancels its guardian.
func (r *RoutedHelperRuntimeV3) Serve(ctx context.Context, c *net.UnixConn, apiPID int32) error {
	if r == nil || ctx == nil || c == nil {
		if c != nil {
			_ = c.Close()
		}
		return ErrIdentity
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.session == nil || r.ctx == nil {
		_ = c.Close()
		return ErrUnavailable
	}
	call, cancel := context.WithCancel(r.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return r.session.ServeInheritedRoutedV3(call, c, r.identities.APIUID, r.identities.APIGID, apiPID, r.metadata.RunID)
}

// Close releases only helper reader descriptors. It cannot delete policy,
// remove namespaces/listeners, publish configuration or stop a guardian.
func (r *RoutedHelperRuntimeV3) Close() error {
	if r == nil {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var failures []error
	if r.fence != nil {
		failures = append(failures, r.fence.Close())
	}
	for _, pool := range r.pools {
		if pool != nil {
			failures = append(failures, pool.Close())
		}
	}
	return errors.Join(failures...)
}
