//go:build !linux

package adminclient

import "os"

// The appliance CLI requires Linux ownership checks; other platforms fail closed.
func openCredentials(string) (*os.File, error) { return nil, ErrCredentials }
