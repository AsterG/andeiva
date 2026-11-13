//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func scopeRecoveryDuplicateV3(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrIdentity
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil || fd < 0 {
		return nil, ErrIdentity
	}
	return os.NewFile(uintptr(fd), "root-retained-scope"), nil
}

// Called only after exact selected-scope authorization and cgroup drainage.
// CLONE_FS isolates the thread's filesystem view; that thread is never returned
// to Go's scheduler. Paths resolve from the authenticated retained directory FD.
func (r *RoutedScopeRecoveryV3) detachNamespaceV3(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // CLONE_FS is not reversible; retire the locked thread.
		done <- r.detachNamespaceThreadV3(ctx)
	}()
	return <-done
}
func (r *RoutedScopeRecoveryV3) detachNamespaceThreadV3(ctx context.Context) (result error) {
	current, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		return err
	}
	defer current.Close()
	if !scopeRecoveryNamespaceV3(current, unix.CLONE_NEWNS) || !scopeRecoveryNamespaceV3(r.files[2], unix.CLONE_NEWNS) {
		return ErrIdentity
	}
	if err = unix.Unshare(unix.CLONE_FS); err != nil {
		return err
	}
	if err = unix.Setns(int(r.files[2].Fd()), unix.CLONE_NEWNS); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Setns(int(current.Fd()), unix.CLONE_NEWNS)) }()
	actual, err := namespaceID("/proc/thread-self/ns/mnt")
	if err != nil || actual != r.record.Mount.Inode || ctx.Err() != nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", r.files[4].Fd()))
	if err != nil {
		return err
	}
	defer area.Close()
	before, err := r.files[4].Stat()
	if err != nil {
		return err
	}
	after, err := area.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return ErrIdentity
	}
	// Reuse the namespace owner's exact pin/underlay checks; no absence shortcut.
	n := &RoutedGatewayNamespaceV3{area: area, identity: r.record.Metadata.GatewayNamespace}
	n.directory, err = scopeRecoveryDuplicateV3(r.files[4])
	if err != nil {
		return err
	}
	n.underlay, err = scopeRecoveryDuplicateV3(r.files[3])
	if err != nil {
		_ = n.directory.Close()
		return err
	}
	n.pin, err = scopeRecoveryDuplicateV3(r.files[1])
	if err != nil {
		_ = n.directory.Close()
		_ = n.underlay.Close()
		return err
	}
	if err = n.Close(); err != nil {
		// Close only these local duplicates after an uncertain detach. The original
		// seven pins and manager copies remain retained; no receipt follows.
		_ = n.directory.Close()
		_ = n.underlay.Close()
		_ = n.pin.Close()
		return err
	}
	return ctx.Err()
}
