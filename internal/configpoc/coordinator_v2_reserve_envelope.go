package configpoc

import (
	"strings"
	"time"
)

// The declaration registry and functional configuration keep their own bound.
// Reserved descriptors/open IDs use the independently tested second half of
// the 256 KiB envelope; ordinary registry growth cannot spend closing space.
func reserveMetadataCoreV2(st v2State) v2State {
	core := st
	core.ActiveReserves = nil
	core.SystemBundle = nil
	core.ClosingCredits = nil
	core.Namespaces = make([]v2Namespace, 0, len(st.Namespaces))
	for _, namespace := range st.Namespaces {
		if namespace.ClosingOrigin != "" {
			continue
		}
		namespace.Open = nil
		namespace.ClosingOpen = nil
		core.Namespaces = append(core.Namespaces, namespace)
	}
	if st.Configuration != nil {
		cfg := *st.Configuration
		cfg.Intent = nil
		cfg.Pending = nil
		core.Configuration = &cfg
	}
	reserveNormalizeEnvelopeScalarsV2(&core)
	return core
}

// Registry growth cannot spend bytes needed for a previously empty history
// root or a generation/sequence digit boundary during reserved closing.
func reserveNormalizeEnvelopeScalarsV2(st *v2State) {
	hash := strings.Repeat("f", 64)
	high := ^uint64(0)
	st.Generation, st.HighWater, st.NamespaceSequence, st.SubjectSequence = high, high, high, high
	st.ReservedBytes, st.ReservedInodes, st.OccupiedOrdinary, st.OccupiedClosing = high, high, high, high
	st.Clock = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	st.Index, st.ClosingIndexRoot, st.ReserveArchiveRoot, st.Migration = hash, hash, hash, hash
	// Preserve all selected sticky features in the byte forecast.
	st.RequiredFeatures = append([]string(nil), st.RequiredFeatures...)
	addFeatureV2(st, v2BootFeature)
	addFeatureV2(st, v2LocalFeature)
	addFeatureV2(st, v2ReserveCompensationFeature)
	if st.Configuration != nil {
		cfg := *st.Configuration
		cfg.AuditSequence = high
		cfg.Firewall.Generation = high
		cfg.LocalServices.Generation = high
		cfg.AuditTip, cfg.LastRecovery, cfg.LastCompletedBoot, cfg.RecoveryIndex, cfg.VerifiedIndex = hash, hash, hash, hash, hash
		cfg.RecoveryRequired = false
		st.Configuration = &cfg
	}
}

func reserveMetadataStateFitsV2(st v2State) bool {
	data, _, err := v2Canonical(st)
	if err != nil || len(data) > reserveMetadataObjectLimitV2 {
		return false
	}
	data, _, err = v2Canonical(reserveMetadataCoreV2(st))
	return err == nil && len(data) <= 128*1024
}
