//go:build linux

package previewruntime

import (
	"net"
	"os"
	"strings"
	"time"
)

func notifyReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" || (!strings.HasPrefix(address, "/") && !strings.HasPrefix(address, "@")) {
		return ErrConfiguration
	}
	c, e := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if e != nil {
		return ErrUnavailable
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, e = c.Write([]byte("READY=1"))
	return e
}
