package networkexecutor

import (
	"encoding/hex"
	"strings"
)

// Identity syntax is shared by portable configuration formats. Valid syntax
// grants no namespace access; Linux constructors verify the real descriptors,
// process identity and capabilities separately.
func validOwnedIdentity(want OwnedNamespaceIdentity) bool {
	if want.UID == 0 || want.GID == 0 || want.Namespace == 0 || want.Host == 0 || want.Namespace == want.Host || len(want.RunID) != 32 || len(want.BootID) != 36 {
		return false
	}
	if want.BootID[8] != '-' || want.BootID[13] != '-' || want.BootID[18] != '-' || want.BootID[23] != '-' {
		return false
	}
	for _, value := range []string{want.RunID, strings.ReplaceAll(want.BootID, "-", "")} {
		if value != strings.ToLower(value) {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
	}
	return len(strings.ReplaceAll(want.BootID, "-", "")) == 32
}
