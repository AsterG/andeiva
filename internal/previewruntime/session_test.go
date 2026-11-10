package previewruntime

import (
	"testing"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestReadOnlyMessagesRejectLocalServicePayload(t *testing.T) {
	for _, verb := range []string{"state", "observe", "recovered"} {
		m := firewallipc.Message{Verb: verb}
		if !ValidMessage(m) {
			t.Fatal("empty read-only request rejected", verb)
		}
		m.Revision.Config.LocalServices = &localpolicy.Config{}
		if ValidMessage(m) {
			t.Fatal("hidden local-service payload accepted", verb)
		}
		m.Revision.Config.LocalServices = nil
		m.Previous.Config.LocalServices = &localpolicy.Config{}
		if ValidMessage(m) {
			t.Fatal("hidden previous local-service payload accepted", verb)
		}
	}
}
