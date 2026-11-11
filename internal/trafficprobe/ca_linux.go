//go:build linux

package trafficprobe

import (
	"os"
	"syscall"
)

func openCAFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- explicit operator CA path, checked ancestors and descriptor identity; no links or blocking special files.
}
