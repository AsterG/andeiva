//go:build linux

package previewruntime

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

// This is the configuration writer's existing lock, never a parallel lock or
// new journal. Root opens it readonly and keeps the exclusive flock until every
// selected check, namespace effect and receipt write has completed.
type scopeRecoveryBarrierV3 struct {
	resource   RoutedReaderRootV3
	identities Identities
	file       *os.File
	identity   RoutedScopeRecoveryFileV3
}

func openScopeRecoveryBarrierV3(ctx context.Context, resource RoutedReaderRootV3, ids Identities) (out *scopeRecoveryBarrierV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || ids.Validate() != nil || resource.Access.OwnerUID != ids.APIUID || resource.Access.CheckDirectory(resource.Root) != nil {
		return nil, ErrIdentity
	}
	file, err := resource.Root.OpenFile("checkpoint.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	b := &scopeRecoveryBarrierV3{resource: resource, identities: ids, file: file}
	defer func() {
		if result != nil {
			_ = b.Close()
		}
	}()
	identity, _, err := scopeRecoveryIdentityV3(file)
	if err != nil {
		return nil, err
	}
	b.identity = identity
	if err = b.check(ctx); err != nil {
		return nil, err
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, ErrUnavailable
	}
	if err = b.check(ctx); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *scopeRecoveryBarrierV3) check(ctx context.Context) error {
	if b == nil || b.file == nil || ctx == nil || ctx.Err() != nil || b.resource.Access.CheckDirectory(b.resource.Root) != nil {
		return ErrIdentity
	}
	identity, st, err := scopeRecoveryIdentityV3(b.file)
	if err != nil || identity != b.identity || st.Mode != unix.S_IFREG|0600 || st.Uid != b.identities.APIUID || (st.Gid != b.identities.APIGID && st.Gid != b.resource.Access.ReaderGID) || st.Size != 0 || st.Nlink != 1 || identity.Device != b.resource.Access.Device || !fenceNoACLV3(b.file, false) {
		return ErrIdentity
	}
	named, err := b.resource.Root.Lstat("checkpoint.lock")
	if err != nil {
		return ErrIdentity
	}
	actual, err := b.file.Stat()
	if err != nil || !os.SameFile(named, actual) {
		return ErrIdentity
	}
	return nil
}
func (b *scopeRecoveryBarrierV3) Close() error {
	if b == nil || b.file == nil {
		return nil
	}
	err := b.file.Close()
	b.file = nil
	return err
}
