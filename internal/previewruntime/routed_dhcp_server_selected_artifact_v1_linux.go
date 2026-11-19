//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"syscall"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

type routedDHCPServerSelectedArtifactV1 struct {
	config    dhcpserver.Config
	bindings  []dhcpkea.Binding
	directory *os.Root
	name      string
	file      *os.File
}

// The broker owns the selection barrier and the private runtime directory.
// Registry and leases are fixed provisioning pins, never paths in a job.
func compileRoutedDHCPServerSelectedArtifactV1(ctx context.Context, identity networkexecutor.OwnedNamespaceIdentity, work configpoc.RoutedWorkReferenceV1, selected RoutedSelectedPreflightResultV4, directory *os.Root, registry, leases *os.File, leaseBudget int64) (_ *routedDHCPServerSelectedArtifactV1, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || directory == nil {
		return nil, ErrIdentity
	}
	plan, err := routedDHCPServerBindingPlanFromSelectedV1(selected, identity, work)
	if err != nil {
		return nil, err
	}
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		return nil, err
	}
	if err := routedDHCPServerLeasesV1(leases, uid, gid, leaseBudget); err != nil {
		return nil, err
	}
	root, err := directory.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	defer root.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &stat) != nil || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Mode != unix.S_IFDIR|0700 || !fenceNoACLV3(root, true) {
		return nil, ErrIdentity
	}
	ids, err := EnsureRoutedDHCPSubnetIDsV1(ctx, registry, leases, plan.subnetBindings())
	if err != nil {
		return nil, err
	}
	bindings, err := plan.keaBindings(ids)
	if err != nil {
		return nil, err
	}
	config := *selected.Bundle.Firewall.Config.Routed.DHCPServer
	artifact, err := dhcpkea.Compile(config, bindings)
	if err != nil || !artifact.Enabled || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrStorage
	}
	name := "dhcp-lan-" + hex.EncodeToString(nonce[:]) + ".json"
	writable, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	prepared := &routedDHCPServerSelectedArtifactV1{
		config: config, bindings: bindings,
		directory: directory, name: name,
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, prepared.closeV1())
		}
	}()
	written, writeErr := writable.Write(artifact.JSON)
	if writeErr != nil || written != len(artifact.JSON) || writable.Chown(0, int(gid)) != nil ||
		writable.Chmod(0440) != nil || writable.Sync() != nil {
		return nil, errors.Join(ErrStorage, writable.Close())
	}
	if err := writable.Close(); err != nil {
		return nil, ErrStorage
	}
	prepared.file, err = directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil || routedDHCPServerConfigFileV1(prepared.file, artifact.JSON, gid) != nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	return prepared, nil
}

// Close after the role and its configuration mounts have been retired. The
// operational directory and its lease data are independent of this artifact.
func (a *routedDHCPServerSelectedArtifactV1) closeV1() error {
	if a == nil {
		return nil
	}
	var err error
	if a.file != nil {
		err = a.file.Close()
		a.file = nil
	}
	if a.name != "" {
		if removeErr := a.directory.Remove(a.name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(err, ErrStorage)
		}
		a.name = ""
	}
	return err
}
