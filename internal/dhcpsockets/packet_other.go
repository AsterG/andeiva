//go:build !linux

package dhcpsockets

import "context"

func CapturePacket(context.Context) ([]PacketSocket, error) { return nil, ErrObservation }
