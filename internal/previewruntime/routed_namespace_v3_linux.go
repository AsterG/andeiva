//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RoutedGatewayNamespaceV3 owns one root-only runtime namespace pin. It does not
// adopt an existing namespace or own any persistent configuration. The supervisor
// must drain its child cgroup before Close; unpinning alone cannot prove that no
// other process retains a namespace descriptor.
type RoutedGatewayNamespaceV3 struct {
	mu                        sync.Mutex
	area                      *os.Root
	directory, underlay, pin  *os.File
	identity                  uint64
	closed, detached, removed bool
	closeStep                 func(string) error // Fault boundaries; nil in supervisor assembly.
}

func (n *RoutedGatewayNamespaceV3) File() *os.File { return n.pin }
func (n *RoutedGatewayNamespaceV3) ID() uint64     { return n.identity }

// createRoutedNetnsFDV3 isolates Unshare on a dedicated goroutine/thread. If
// restoring the host namespace fails, that locked thread exits with the
// goroutine instead of returning contaminated execution to the caller.
func createRoutedNetnsFDV3() (*os.File, error) {
	type result struct {
		file *os.File
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		host, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer host.Close()
		if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- result{err: err}
			return
		}
		restored = false
		pin, openErr := os.Open("/proc/thread-self/ns/net")
		restoreErr := unix.Setns(int(host.Fd()), unix.CLONE_NEWNET)
		if restoreErr == nil {
			restored = true
		}
		if openErr != nil || restoreErr != nil {
			if pin != nil {
				_ = pin.Close()
			}
			ch <- result{err: errors.Join(openErr, restoreErr)}
			return
		}
		ch <- result{file: pin}
	}()
	r := <-ch
	return r.file, r.err
}

// CreateRoutedGatewayNamespaceV3 accepts an empty root-owned 0700 directory
// provided by the root supervisor. Mount operations resolve through its retained
// directory descriptor, never by reopening directory.Name().
func CreateRoutedGatewayNamespaceV3(ctx context.Context, area *os.Root) (out *RoutedGatewayNamespaceV3, result error) {
	if ctx == nil || ctx.Err() != nil || area == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	if trustedRoutedExecutableV3("/usr/bin/nsenter") != nil || trustedRoutedExecutableV3("/usr/sbin/sysctl") != nil {
		return nil, ErrIdentity
	}
	directory, err := area.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = directory.Close()
		}
	}()
	info, err := directory.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 || !fenceNoACLV3(directory, true) {
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
	underlay, err := area.OpenFile("gateway", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	n := &RoutedGatewayNamespaceV3{area: area, directory: directory, underlay: underlay}
	owned = true
	defer func() {
		if result != nil {
			cleanupErr := n.closeUnder(false)
			if cleanupErr != nil {
				if n.pin != nil {
					cleanupErr = errors.Join(cleanupErr, n.pin.Close())
				}
				cleanupErr = errors.Join(cleanupErr, n.underlay.Close(), n.directory.Close())
			}
			result = errors.Join(result, cleanupErr)
		}
	}()
	pin, err := createRoutedNetnsFDV3()
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	var ns unix.Stat_t
	if unix.Fstat(int(pin.Fd()), &ns) != nil || !routedLinkNamespaceV3(pin, ns.Ino) {
		return nil, ErrIdentity
	}
	current, err := namespaceID("/proc/thread-self/ns/net")
	if err != nil || current == ns.Ino || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	target := fmt.Sprintf("/proc/self/fd/%d/gateway", directory.Fd())
	if err = unix.Mount(fmt.Sprintf("/proc/self/fd/%d", pin.Fd()), target, "", unix.MS_BIND, ""); err != nil {
		return nil, err
	}
	n.identity = ns.Ino
	n.pin, err = area.OpenFile("gateway", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil || !routedLinkNamespaceV3(n.pin, n.identity) {
		return nil, ErrIdentity
	}
	// A separate process has both leader and executing thread in the gateway.
	// Never write /proc/sys/net from the temporary Unshare thread above.
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=0", "net.ipv4.conf.default.forwarding=0", "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.default.forwarding=0", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
	cmd.ExtraFiles = []*os.File{n.pin}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	runtime.LockOSThread()
	err = cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	read := exec.CommandContext(call, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward", "net.ipv4.conf.default.forwarding", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6")
	read.ExtraFiles = []*os.File{n.pin}
	read.Env = cmd.Env
	read.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	read.WaitDelay = 200 * time.Millisecond
	var output helperOutput
	read.Stdout = &output
	runtime.LockOSThread()
	err = read.Run()
	runtime.UnlockOSThread()
	if err != nil || output.String() != "0\n0\n0\n0\n1\n1\n" || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	if err = directory.Sync(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *RoutedGatewayNamespaceV3) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closeUnder(true)
}

func (n *RoutedGatewayNamespaceV3) closeUnder(requirePin bool) error {
	if n.closed {
		return nil
	}
	if n.identity != 0 && !n.detached {
		pin, err := n.area.OpenFile("gateway", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		valid := routedLinkNamespaceV3(pin, n.identity)
		_ = pin.Close()
		if !valid {
			return ErrIdentity
		}
		if err = unix.Unmount(fmt.Sprintf("/proc/self/fd/%d/gateway", n.directory.Fd()), unix.MNT_DETACH); err != nil {
			return err
		}
		n.detached = true
		if n.closeStep != nil {
			if err := n.closeStep("after-detach"); err != nil {
				return err
			}
		}
	} else if requirePin && !n.detached {
		return ErrIdentity
	}
	if !n.removed {
		actual, err := n.area.Stat("gateway")
		original, statErr := n.underlay.Stat()
		if err != nil || statErr != nil || !os.SameFile(actual, original) {
			return ErrIdentity
		}
		if err = n.area.Remove("gateway"); err != nil {
			return err
		}
		n.removed = true
		if n.closeStep != nil {
			if err := n.closeStep("after-remove"); err != nil {
				return err
			}
		}
	}
	if err := n.directory.Sync(); err != nil {
		return err
	}
	n.closed = true
	var closeErr error
	if n.pin != nil {
		closeErr = n.pin.Close()
	}
	return errors.Join(closeErr, n.underlay.Close(), n.directory.Close())
}
