//go:build !linux

package trafficprobe

import "os"

func openCAFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- explicit operator CA path; regular-file/ancestor/descriptor checks surround this read.
}
