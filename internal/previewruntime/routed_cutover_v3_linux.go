//go:build linux

package previewruntime

import "os"

const routedCutoverPathV3 = DataDir + "/grouped-cutover.json"

// LegacyRuntimeAllowedV3 prevents an old writer from reopening the retained
// pre-migration snapshot after cutover has started. Even an unreadable, malformed
// or dangling marker requires explicit recovery; absence is the only permission.
func LegacyRuntimeAllowedV3() error { return legacyRuntimeAllowedAtV3(routedCutoverPathV3) }

func legacyRuntimeAllowedAtV3(path string) error {
	_, err := os.Lstat(path) // #nosec G304 -- Production caller supplies the fixed root-owned cutover marker; Lstat never follows it.
	if os.IsNotExist(err) {
		return nil
	}
	return ErrConfiguration
}
