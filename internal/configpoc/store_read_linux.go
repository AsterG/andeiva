//go:build linux

package configpoc

import (
	"os"
	"syscall"
)

func openRecordFile(root *os.Root, name string) (*os.File, error) {
	// A substituted FIFO must not block while the coordinator lock is held.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
