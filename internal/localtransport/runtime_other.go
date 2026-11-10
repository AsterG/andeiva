//go:build !linux

package localtransport

func New(uint64, uint64) (*Transport, error) { return nil, ErrPlatform }
