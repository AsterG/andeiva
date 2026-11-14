//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
	"time"
)

type routedManagedNamespaceV3 struct {
	metadata          Metadata
	area              *os.Root
	host              *os.File
	namespace         *RoutedGatewayNamespaceV3
	links             *RoutedGatewayLinksV3
	namespaceRoot     *os.Root
	children          []string
	metadataInfo      os.FileInfo
	recovery          *RoutedScopeRecoveryV3
	recoveryPublished bool
}

// The caller drains the inherited-resource supervisor before closing this
// namespace owner. Mount pins alone do not prove that helper processes exited.
func (r *routedManagedNamespaceV3) Close() error {
	if r == nil {
		return nil
	}
	var result error
	if r.links != nil {
		result = errors.Join(result, r.links.Close())
	}
	if r.namespace != nil {
		if err := r.namespace.Close(); err != nil {
			return errors.Join(result, err)
		}
		// The exclusively owned namespace was detached after its children were
		// drained. An uncertain individual link no longer prevents FD cleanup.
		r.namespace, r.links = nil, nil
	}
	if r.namespaceRoot != nil {
		result = errors.Join(result, r.namespaceRoot.Close())
		r.namespaceRoot = nil
	}
	if r.host != nil {
		result = errors.Join(result, r.host.Close())
		r.host = nil
	}
	if r.metadataInfo != nil {
		actual, err := r.area.Lstat("runtime.json")
		if err != nil || !os.SameFile(actual, r.metadataInfo) {
			return errors.Join(result, ErrIdentity)
		}
		if err = r.area.Remove("runtime.json"); err != nil {
			return errors.Join(result, err)
		}
		r.metadataInfo = nil
	}
	for len(r.children) > 0 {
		i := len(r.children) - 1
		// Remove refuses nonempty directories; foreign leftovers are retained.
		if err := r.area.Remove(r.children[i]); err != nil {
			return errors.Join(result, err)
		}
		r.children = r.children[:i]
	}
	parent, err := r.area.Open(".")
	if err != nil {
		return errors.Join(result, err)
	}
	entries, readErr := parent.ReadDir(1)
	if len(entries) != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return errors.Join(result, ErrStorage, parent.Close())
	}
	return errors.Join(result, parent.Sync(), parent.Close())
}

// Standalone isolated namespace fixtures do not enable the service FD store.
func prepareRoutedManagedNamespaceV3(ctx context.Context, area *os.Root, node routedNodeLinksV3, ids Identities) (*routedManagedNamespaceV3, error) {
	return prepareRoutedManagedScopeV3(ctx, area, node, ids, nil)
}
func prepareRoutedManagedScopeV3(ctx context.Context, area *os.Root, node routedNodeLinksV3, ids Identities, record *routedScopeRecordSlotV3) (out *routedManagedNamespaceV3, result error) {
	if ctx == nil || ctx.Err() != nil || area == nil || node.validate() != nil || ids.Validate() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	directory, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || info.Mode() != os.ModeDir|0755 || !fenceNoACLV3(directory, true) {
		return nil, ErrIdentity
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return nil, ErrIdentity
	}
	entries, err := directory.ReadDir(1)
	if len(entries) != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return nil, ErrStorage
	}
	r := &routedManagedNamespaceV3{area: area}
	defer func() {
		if result != nil && !r.recoveryPublished {
			result = errors.Join(result, r.Close())
		}
		// Once the manifest is published, preserve uncertain resources for recovery.
		// The root service exits on failure; no receipt or pathname cleanup is inferred.
	}()
	for _, child := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
	}{
		{"netns", 0, 0, 0700}, {"ipc", ids.HelperUID, ids.IPCGID, 0750}, {"api", ids.APIUID, ids.APIGID, 0700},
	} {
		if err = area.Mkdir(child.name, 0700); err != nil {
			return nil, err
		}
		r.children = append(r.children, child.name)
		f, e := area.OpenFile(child.name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		e = f.Chmod(child.mode)
		if e == nil {
			e = f.Chown(int(child.uid), int(child.gid))
		}
		e = errors.Join(e, f.Sync(), f.Close())
		if e != nil {
			return nil, e
		}
	}
	r.namespaceRoot, err = area.OpenRoot("netns")
	if err != nil {
		return nil, err
	}
	r.namespace, err = CreateRoutedGatewayNamespaceV3(ctx, r.namespaceRoot)
	if err != nil {
		return nil, err
	}
	r.host, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	bootID, err := canonicalBoot(boot)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	r.metadata = Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: hex.EncodeToString(nonce[:]), BootID: bootID, HostNamespace: host, GatewayNamespace: r.namespace.ID()}
	if err = writeNew(area, "runtime.json", marshal(r.metadata), 0644, 0, 0); err != nil {
		return nil, err
	}
	r.metadataInfo, err = area.Lstat("runtime.json")
	if err != nil {
		return nil, err
	}
	if err = directory.Sync(); err != nil {
		return nil, err
	}
	if record != nil {
		if err = r.publishScopeV3(ctx, record, ids); err != nil {
			return nil, err
		}
	}
	r.links, err = NewRoutedGatewayLinksV3(ctx, r.metadata, r.host, r.namespace.File(), [2]RoutedParentLinkV3{node.LAN.binding(), node.WAN.binding()}, node.Identity)
	if err != nil {
		return nil, err
	}
	if err = r.links.Create(ctx); err != nil {
		return nil, err
	}
	if err = r.links.Enable(ctx); err != nil {
		return nil, err
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = directory.Sync(); err != nil {
		return nil, err
	}
	return r, nil
}

// RunRoutedManagedSupervisorV3 binds a new, exclusively owned gateway to the
// inherited-resource supervisor. A root cutover record pins both operational
// manifests; selected-state validation and real boot readback remain mandatory.
func RunRoutedManagedSupervisorV3(ctx context.Context, c Config) (result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return ErrIdentity
	}
	inherited, err := TakeRoutedScopeRecoveryInheritedV3(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, inherited.Close()) }()
	marker, err := readOwned(routedCutoverPathV3, 0, 0, 0600, 4096)
	if err != nil {
		return err
	}
	deployment, err := readOwned(routedDeploymentPathV3, 0, 0, 0600, 16384)
	if err != nil {
		return err
	}
	links, err := readOwned(routedNodeLinksPathV3, 0, 0, 0600, 4096)
	if err != nil {
		return err
	}
	if verifyRoutedCutoverV3(marker, deployment, links) != nil {
		return ErrIdentity
	}
	node, err := decodeRoutedNodeLinksV3(links)
	if err != nil {
		return err
	}
	ids, err := LoadIdentities(c)
	if err != nil {
		return err
	}
	if _, err = decodeRoutedDeploymentV3(deployment, ids); err != nil {
		return err
	}
	if safeParents(routedRetirementDirectoryV3+"/"+routedRetirementSlotV3) != nil {
		return ErrIdentity
	}
	operational, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, operational.Close()) }()
	// Startup never creates the slot: installation must reserve it before any
	// network effects. The service has write access to this exact file only.
	if _, err = operational.Lstat(routedRetirementSlotV3); err != nil {
		return err
	}
	slot, err := openRoutedRetirementSlotV3(operational)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, slot.Close()) }()
	if safeParents(routedDeploymentRunV3+"/runtime.json") != nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(routedDeploymentRunV3)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, area.Close()) }()
	record, err := openScopeRecordSlotV3(operational, false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, record.Close()) }()
	if inherited.Recovery != nil {
		if err = retireInheritedRoutedScopeV3(ctx, c, area, slot, record, inherited.Recovery, ids); err != nil {
			return err
		}
	}
	if err = record.clearCompleted(ctx, slot); err != nil {
		return err
	}
	owned, err := prepareRoutedManagedScopeV3(ctx, area, node, ids, record)
	if err != nil {
		return err
	}
	defer func() {
		// Retain pins and files if a descendant may still mutate the old scope.
		result = errors.Join(result, finishStoredRoutedScopeV3(slot, record, owned, ids))
	}()
	// RunRoutedSupervisorV3 drains both child processes before returning. Only
	// then may the namespace owner remove links and release its mount pin.
	return runRoutedSupervisorWithManagementV3(ctx, c, inherited.Management)
}

func (r *routedManagedNamespaceV3) publishScopeV3(ctx context.Context, record *routedScopeRecordSlotV3, ids Identities) error {
	// Reopen only a previously verified retained underlay descriptor as readonly.
	// Its pathname is never used as authority.
	underlay, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", r.namespace.underlay.Fd()))
	if err != nil {
		return err
	}
	defer underlay.Close()
	oldInfo, err := r.namespace.underlay.Stat()
	newInfo, e := underlay.Stat()
	if err != nil || e != nil || !os.SameFile(oldInfo, newInfo) {
		return ErrIdentity
	}
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	defer mount.Close()
	cgroup, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		return err
	}
	defer cgroup.Close()
	eventsFD, err := unix.Openat(int(cgroup.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	events := os.NewFile(uintptr(eventsFD), "root-cgroup-events")
	defer events.Close()
	anchors := RoutedScopeRecoveryAnchorsV3{record.reader, r.namespace.File(), mount, underlay, r.namespace.directory, cgroup, events}
	raw, err := PrepareRoutedScopeRecoveryRecordV3(ctx, r.metadata, ids, anchors)
	if err != nil {
		return err
	}
	if err = record.publish(raw); err != nil {
		return err
	}
	r.recoveryPublished = true
	r.recovery, err = OpenRoutedScopeRecoveryV3(ctx, anchors)
	if err != nil {
		return err
	}
	return r.recovery.Store(ctx)
}
func finishStoredRoutedScopeV3(slot *routedRetirementSlot, record *routedScopeRecordSlotV3, owned *routedManagedNamespaceV3, ids Identities) error {
	if slot == nil || record == nil || owned == nil || owned.recovery == nil {
		return ErrIdentity
	}
	if err := waitRoutedCgroupDrainedV3(); err != nil {
		return err
	}
	if err := owned.Close(); err != nil {
		return err
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := owned.recovery.DropStored(cleanup); err != nil {
		return err
	}
	if err := owned.recovery.Close(); err != nil {
		return err
	}
	if err := slot.recordDrained(owned.metadata, ids); err != nil {
		return err
	}
	return record.clearCompleted(cleanup, slot)
}
