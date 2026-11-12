package networkplan

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const MaxDocumentBytes = 64 << 10

// Decode accepts one bounded object, refusing unknown, duplicated and aliased
// control fields. It does not accept observed inventory or execution evidence.
func Decode(data []byte) (Revision, error) {
	if len(data) > MaxDocumentBytes || !jsoncheck.UniqueControlFields(data) {
		return Revision{}, invalid("DOCUMENT", "document")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var config Config
	if d.Decode(&config) != nil || d.Decode(new(any)) != io.EOF {
		return Revision{}, invalid("DOCUMENT", "document")
	}
	return Canonical(config)
}
