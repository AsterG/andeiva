package nftfixture

import (
	"errors"
	"os"
	"syscall"
)

func enableForwarding(host uint64) error {
	gatewayHandle := os.NewFile(3, "gateway-namespace")
	hostHandle := os.NewFile(4, "host-namespace")
	defer gatewayHandle.Close()
	defer hostHandle.Close()
	// Reject missing inherited handles before opening any file that could reuse
	// their descriptor numbers and accidentally satisfy the gateway check.
	if _, err := networkNamespaceInode(3); err != nil {
		return err
	}
	if _, err := networkNamespaceInode(4); err != nil {
		return err
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer self.Close()
	if os.Geteuid() != 0 {
		return errors.New("ANDEIVA_NFT_FIXTURE_HOST_NAMESPACE")
	}
	if err := validateForwardNamespaces(host, int(self.Fd()), 3, 4); err != nil {
		return err
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600)
}

// The trusted supervisor supplies gateway FD3 and its retained original host
// FD4. No API caller chooses either descriptor or the expected host identity.
func validateForwardNamespaces(host uint64, currentFD, gatewayFD, hostFD int) error {
	current, currentErr := networkNamespaceInode(currentFD)
	gateway, gatewayErr := networkNamespaceInode(gatewayFD)
	original, hostErr := networkNamespaceInode(hostFD)
	if currentErr != nil || gatewayErr != nil || hostErr != nil || !validForwardIdentity(host, current, gateway, original) {
		return errors.New("ANDEIVA_NFT_FIXTURE_HOST_NAMESPACE")
	}
	return nil
}

func validForwardIdentity(expectedHost, current, gateway, original uint64) bool {
	return expectedHost != 0 && current != 0 && original == expectedHost && current == gateway && current != original
}

func networkNamespaceInode(fd int) (uint64, error) {
	var fs syscall.Statfs_t
	var st syscall.Stat_t
	if fd < 0 || syscall.Fstatfs(fd, &fs) != nil || fs.Type != 0x6e736673 || syscall.Fstat(fd, &st) != nil || st.Ino == 0 {
		return 0, errors.New("ANDEIVA_NFT_FIXTURE_NAMESPACE_DESCRIPTOR")
	}
	// NS_GET_NSTYPE distinguishes a network namespace from other nsfs objects.
	kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xb703, 0)
	if errno != 0 || kind != syscall.CLONE_NEWNET {
		return 0, errors.New("ANDEIVA_NFT_FIXTURE_NAMESPACE_DESCRIPTOR")
	}
	return st.Ino, nil
}

func armParentDeath(host uint64) error {
	self, err := inode("/proc/self/ns/net")
	if err != nil {
		return err
	}
	pinned, err := inode("/proc/self/fd/3")
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 || host == 0 || self != pinned || self == host {
		return errors.New("ANDEIVA_NFT_FIXTURE_IDENTITY")
	}
	parent := os.Getppid()
	if parent <= 1 {
		return errors.New("ANDEIVA_NFT_FIXTURE_ORPHAN")
	}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 1, uintptr(syscall.SIGKILL), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if os.Getppid() != parent {
		return errors.New("ANDEIVA_NFT_FIXTURE_ORPHAN")
	}
	return nil
}
