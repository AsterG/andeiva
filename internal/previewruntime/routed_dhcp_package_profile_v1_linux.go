//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const routedDHCPPackageLeaseBudgetV1 = 4 << 20

func (r *routedDeploymentResourcesV3) attachDHCPPackageProfileV1(ctx context.Context) error {
	if os.Getenv(routedDHCPRoleProfileEnvV1) != "1" {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || r == nil || r.launch.IntegrityRoot == nil {
		return ErrIdentity
	}
	if safeParents(routedRetirementDirectoryV3+"/"+routedDHCPPackageDirectoryV1) != nil ||
		safeParents(routedDeploymentRunV3+"/"+routedDHCPPackageDirectoryV1) != nil {
		return ErrStorage
	}
	packageRoot, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return ErrStorage
	}
	defer packageRoot.Close()
	registry, err := packageRoot.OpenFile(routedDHCPPackageDirectoryV1, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrStorage
	}
	r.files = append(r.files, registry)
	if !routedDHCPPackageDirectoryOwnedV1(registry, 0, 0) {
		return ErrIdentity
	}
	fd, err := unix.Openat(int(registry.Fd()), routedDHCPPackageLeasesV1, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrStorage
	}
	leases := os.NewFile(uintptr(fd), "kea-operational-leases")
	r.files = append(r.files, leases)
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil || !routedDHCPPackageDirectoryOwnedV1(leases, uid, gid) {
		return ErrIdentity
	}
	area, err := os.OpenRoot(routedDeploymentRunV3)
	if err != nil {
		return ErrStorage
	}
	defer area.Close()
	if err := area.Mkdir(routedDHCPPackageDirectoryV1, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrStorage
	}
	before, err := area.Lstat(routedDHCPPackageDirectoryV1)
	if err != nil || !before.IsDir() {
		return ErrIdentity
	}
	runtime, err := area.OpenRoot(routedDHCPPackageDirectoryV1)
	if err != nil {
		return ErrStorage
	}
	r.roots = append(r.roots, runtime)
	after, err := runtime.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return ErrIdentity
	}
	runtimePin, err := runtime.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrStorage
	}
	owned := routedDHCPPackageDirectoryOwnedV1(runtimePin, 0, 0)
	entries, err := runtimePin.Readdirnames(1)
	_ = runtimePin.Close()
	if !owned || len(entries) != 0 || err != io.EOF {
		return ErrIdentity
	}
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return ErrIdentity
	}
	r.files = append(r.files, mount)
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrUnavailable
	}
	services, err := PrepareRoutedDHCPServerServiceSetV1(ctx, RoutedDHCPServerServiceSetOptionsV1{
		WANEnabled: true, LANEnabled: true, WANIncarnation: hex.EncodeToString(nonce[:16]), LANIncarnation: hex.EncodeToString(nonce[16:]),
	})
	if err != nil {
		return err
	}
	r.launch.DHCPJobs, r.launch.DHCPRenewalV4, r.launch.DHCPServiceSet = true, true, services
	r.launch.dhcpServer = &routedDHCPServerSelectedOptionsV1{
		hostMount: mount, runtime: runtime, registry: registry, leases: leases, leaseBudget: routedDHCPPackageLeaseBudgetV1,
	}
	return nil
}

func (r *routedDeploymentResourcesV3) retireDHCPPackageProfileV1() error {
	if r.launch.DHCPServiceSet == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), routedDHCPServerStopGraceV1)
	defer cancel()
	return r.launch.DHCPServiceSet.DestroyV1(ctx)
}
