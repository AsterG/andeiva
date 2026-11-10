//go:build !linux

package localobserve

import "os"

type Collector struct{}

func New(*os.Process, Expected) (*Collector, error) { return nil, ErrPlatform }
func (*Collector) Observe() (Snapshot, error)       { return Snapshot{}, ErrPlatform }
func (*Collector) Close() error                     { return nil }
