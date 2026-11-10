package firewallipc

import "encoding/hex"

func validLocalObservation(r Reply) bool {
	validHash := func(value string) bool {
		b, err := hex.DecodeString(value)
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
	}
	// Full policy reconciliation remains mandatory at the domain boundary. These
	// checks bound the transport and prevent cross-domain or incomplete replies.
	return r.Local != nil && validHash(r.Hash) && validHash(r.Local.Revision) &&
		len(r.Local.Listeners) <= 8 && len(r.Local.Rules) <= 128
}
