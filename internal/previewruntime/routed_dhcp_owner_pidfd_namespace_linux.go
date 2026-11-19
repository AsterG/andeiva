//go:build linux

package previewruntime

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type routedDHCPPinnedNamespacesV1 struct {
	mount *os.File
	netID uint64
	err   error
}

// The opted-in supervisor retains the permitted capabilities needed for
// setns(pidfd), while opening /proc/PID/ns directly requires them effective.
// Only a private, non-leader thread enters the kernel-pinned child's namespaces.
func readRoutedDHCPPinnedNamespacesV1(pidfd *os.File, withNetwork bool) routedDHCPPinnedNamespacesV1 {
	if pidfd == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return routedDHCPPinnedNamespacesV1{err: ErrIdentity}
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return routedDHCPPinnedNamespacesV1{err: err}
	}
	defer proc.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(proc.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return routedDHCPPinnedNamespacesV1{err: ErrIdentity}
	}
	end := make(chan routedDHCPPinnedNamespacesV1, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			// Keep the leader parked until the inspecting goroutine has selected
			// a different thread. The leader remains visible in /proc/PID/ns.
			defer runtime.UnlockOSThread()
			private := make(chan routedDHCPPinnedNamespacesV1, 1)
			go func() {
				runtime.LockOSThread()
				private <- readRoutedDHCPPinnedNamespacesOnThreadV1(proc, pidfd, withNetwork)
			}()
			end <- <-private
			return
		}
		end <- readRoutedDHCPPinnedNamespacesOnThreadV1(proc, pidfd, withNetwork)
	}()
	return <-end
}

// The locked thread is retired on exit. Procfs is pinned before entering the
// child, so paths cannot select a mount supplied by the child.
func readRoutedDHCPPinnedNamespacesOnThreadV1(proc, pidfd *os.File, withNetwork bool) (out routedDHCPPinnedNamespacesV1) {
	if unix.Gettid() == os.Getpid() {
		return routedDHCPPinnedNamespacesV1{err: ErrIdentity}
	}
	open := func(kind string) (*os.File, error) {
		fd, err := unix.Openat(int(proc.Fd()), "thread-self/ns/"+kind, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), kind), nil
	}
	originalMount, err := open("mnt")
	if err != nil {
		return routedDHCPPinnedNamespacesV1{err: err}
	}
	defer originalMount.Close()
	flags := unix.CLONE_NEWNS
	var originalNet *os.File
	if withNetwork {
		originalNet, err = open("net")
		if err != nil {
			return routedDHCPPinnedNamespacesV1{err: err}
		}
		defer originalNet.Close()
		flags |= unix.CLONE_NEWNET
	}
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return routedDHCPPinnedNamespacesV1{err: err}
	}
	if err := unix.Setns(int(pidfd.Fd()), flags); err != nil {
		return routedDHCPPinnedNamespacesV1{err: err}
	}
	defer func() {
		out.err = errors.Join(out.err, unix.Setns(int(originalMount.Fd()), unix.CLONE_NEWNS))
		if originalNet != nil {
			out.err = errors.Join(out.err, unix.Setns(int(originalNet.Fd()), unix.CLONE_NEWNET))
		}
		if out.err != nil && out.mount != nil {
			_ = out.mount.Close()
			out.mount = nil
		}
	}()
	out.mount, out.err = open("mnt")
	if out.err != nil || !withNetwork {
		return out
	}
	net, err := open("net")
	if err != nil {
		out.err = err
		return out
	}
	defer net.Close()
	out.netID, out.err = routedDHCPNamespaceFileIDV1(net, unix.CLONE_NEWNET)
	return out
}

func routedDHCPNamespaceFileIDV1(f *os.File, kind int) (uint64, error) {
	if f == nil {
		return 0, ErrIdentity
	}
	var stat unix.Stat_t
	if unix.Fstat(int(f.Fd()), &stat) != nil || stat.Ino == 0 || !routedDHCPOwnerNamespaceV3(f, kind, stat.Ino) {
		return 0, ErrIdentity
	}
	return stat.Ino, nil
}
