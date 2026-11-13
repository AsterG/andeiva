//go:build linux

package previewruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const routedCutoverPathV3 = DataDir + "/grouped-cutover.json"

type routedCutoverRecordV3 struct {
	Version          int    `json:"version"`
	DeploymentSHA256 string `json:"deployment_sha256"`
	LinksSHA256      string `json:"links_sha256"`
}

func verifyRoutedCutoverV3(marker, deployment, links []byte) error {
	var record routedCutoverRecordV3
	digest, linkDigest := sha256.Sum256(deployment), sha256.Sum256(links)
	if len(marker) == 0 || len(marker) > 4096 || len(deployment) == 0 || len(links) == 0 || !jsoncheck.UniqueControlFields(marker) || firewallipc.Decode(marker, &record) != nil || record.Version != 1 || record.DeploymentSHA256 != hex.EncodeToString(digest[:]) || record.LinksSHA256 != hex.EncodeToString(linkDigest[:]) {
		return ErrIdentity
	}
	return nil
}

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
