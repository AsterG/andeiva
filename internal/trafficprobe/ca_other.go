//go:build !linux

package trafficprobe

import "os"

const customCASupported = false

// Refuse custom trust files until this platform has a qualified safe opener.
// In particular, never fall back to a potentially blocking os.Open.
func openCAFile(string) (*os.File, error) {
	return nil, errInvalid
}
