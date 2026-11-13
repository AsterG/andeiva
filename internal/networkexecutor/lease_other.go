//go:build !linux

package networkexecutor

import (
	"context"
	"os"
)

func NewLeaseInOwnedNamespace(context.Context, *os.File, *os.File, OwnedNamespaceIdentity, uint32, LeaseOptions) (*LeaseExecutor, error) {
	return nil, ErrUnsupported
}
