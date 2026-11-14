//go:build !linux

package dhcpsockets

import "context"

func CaptureIPv4UDP(context.Context) ([]Socket, error) { return nil, ErrObservation }
