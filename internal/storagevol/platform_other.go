//go:build !linux

package storagevol

import "context"

func Prepare(context.Context) (Manifest, error)         { return Manifest{}, ErrPlatform }
func Inspect(context.Context, string) (Manifest, error) { return Manifest{}, ErrPlatform }
