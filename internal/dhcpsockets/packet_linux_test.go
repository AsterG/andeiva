//go:build linux

package dhcpsockets

import (
	"context"
	"testing"
	"time"
)

func TestPacketInventoryReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := CapturePacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uniquePackets(rows); err != nil {
		t.Fatal(err)
	}
}
