package nftfixture

import (
	"errors"
	"os"
	"syscall"
)

func enableForwarding(host uint64) error {
	self, err := inode("/proc/self/ns/net")
	if err != nil {
		return err
	}
	init, err := inode("/proc/1/ns/net")
	if err != nil {
		return err
	}
	pinned, err := inode("/proc/self/fd/3")
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || host == 0 || self == host || self == init || self != pinned {
		return errors.New("ANDEIVA_NFT_FIXTURE_HOST_NAMESPACE")
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600)
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
