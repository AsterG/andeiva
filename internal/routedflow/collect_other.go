//go:build !linux

package routedflow

import "context"

func Collect(_ context.Context) (Snapshot, error) { return Snapshot{}, ErrUnsupported }
