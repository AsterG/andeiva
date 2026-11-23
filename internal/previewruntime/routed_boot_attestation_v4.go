package previewruntime

import (
	"bytes"
	"encoding/json"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const (
	routedBootAttestationLimitV4   = 8
	routedBootAttestedRecordV4     = "scope_record"
	routedBootAttestedReceiptV4    = "drain_receipt"
	routedBootAttestationVersionV4 = 5
)

// RootBootAttestedScopeV4 names one scope that root itself recorded during an
// earlier kernel boot. SourceSHA256 is the digest of the fixed-size root record
// that named it. The entry carries no drain time: none was observed.
type RootBootAttestedScopeV4 struct {
	Old            networkexecutor.OwnedNamespaceIdentity `json:"old"`
	MetadataSHA256 string                                 `json:"metadata_sha256"`
	Source         string                                 `json:"source"`
	LineageSHA256  string                                 `json:"lineage_sha256"`
	SourceSHA256   string                                 `json:"source_sha256"`
}

// RootBootAttestationV4 occupies the retirement slot when a scope ended without
// an orderly drain receipt and the kernel has since booted again. Root writes it
// from its own persisted scope record and the boot identity it read from procfs.
// It states only that the listed scopes belong to other boots of this
// provisioned installation. It is never accepted for a scope of the same boot.
type RootBootAttestationV4 struct {
	Version         int                       `json:"version"`
	BootID          string                    `json:"boot_id"`
	Identities      Identities                `json:"identities"`
	Retired         []RootBootAttestedScopeV4 `json:"retired"`
	IntegritySHA256 string                    `json:"integrity_sha256,omitempty"`
}

func (a RootBootAttestationV4) valid() bool {
	boot, err := canonicalBoot([]byte(a.BootID))
	if a.Version != routedBootAttestationVersionV4 || err != nil || boot != a.BootID || a.Identities.Validate() != nil || len(a.Retired) == 0 || len(a.Retired) > routedBootAttestationLimitV4 {
		return false
	}
	seen := map[networkexecutor.OwnedNamespaceIdentity]bool{}
	for _, entry := range a.Retired {
		if !retirementIdentityV3(entry.Old) || entry.Old.BootID == a.BootID || entry.Old.UID != a.Identities.HelperUID || entry.Old.GID != a.Identities.IPCGID || seen[entry.Old] ||
			!retirementHashV3(entry.LineageSHA256) || !retirementHashV3(entry.MetadataSHA256) || !retirementHashV3(entry.SourceSHA256) || entry.Source != routedBootAttestedRecordV4 && entry.Source != routedBootAttestedReceiptV4 {
			return false
		}
		seen[entry.Old] = true
	}
	return true
}

func (a RootBootAttestationV4) matchesLineage(digest string) bool {
	if !retirementHashV3(digest) {
		return false
	}
	for _, entry := range a.Retired {
		if entry.LineageSHA256 != digest {
			return false
		}
	}
	return true
}

func (a RootBootAttestationV4) retired(old networkexecutor.OwnedNamespaceIdentity) (RootBootAttestedScopeV4, bool) {
	for _, entry := range a.Retired {
		if entry.Old == old {
			return entry, true
		}
	}
	return RootBootAttestedScopeV4{}, false
}

// EncodeRootBootAttestationV4 returns the exact fixed-size slot content. The
// digest detects a torn write; root ownership of the slot authenticates it.
func EncodeRootBootAttestationV4(a RootBootAttestationV4) ([]byte, error) {
	if !a.valid() || a.IntegritySHA256 != "" {
		return nil, ErrIdentity
	}
	unsigned, err := json.Marshal(a)
	if err != nil {
		return nil, ErrIdentity
	}
	a.IntegritySHA256 = retirementDigestV3(unsigned)
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > RootRetirementReceiptSizeV3 {
		return nil, ErrIdentity
	}
	return append(raw, bytes.Repeat([]byte{' '}, RootRetirementReceiptSizeV3-len(raw))...), nil
}

// DecodeRootBootAttestationV4 accepts only the exact encoding emitted above.
func DecodeRootBootAttestationV4(raw []byte) (RootBootAttestationV4, error) {
	var a RootBootAttestationV4
	if len(raw) != RootRetirementReceiptSizeV3 {
		return a, ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || !retirementHashV3(a.IntegritySHA256) {
		return RootBootAttestationV4{}, ErrIdentity
	}
	unsigned := a
	unsigned.IntegritySHA256 = ""
	expected, err := EncodeRootBootAttestationV4(unsigned)
	if err != nil || !bytes.Equal(raw, expected) {
		return RootBootAttestationV4{}, ErrIdentity
	}
	return a, nil
}

func routedSlotZeroV4(raw []byte) bool {
	return len(raw) == RootRetirementReceiptSizeV3 && bytes.Equal(raw, make([]byte, RootRetirementReceiptSizeV3))
}

func routedScopeRecordIdentityV4(r RoutedScopeRecoveryRecordV3) networkexecutor.OwnedNamespaceIdentity {
	return networkexecutor.OwnedNamespaceIdentity{UID: r.Identities.HelperUID, GID: r.Identities.IPCGID, Namespace: r.Metadata.GatewayNamespace, Host: r.Metadata.HostNamespace, BootID: r.Metadata.BootID, RunID: r.Metadata.RunID}
}

// routedBootAttestationNextV4 decides whether root must write an attestation
// before the persisted scope record may be released. kernel is the identity
// root just read from procfs. A record of the running boot is a service
// restart: nothing is issued and the orderly drain receipt stays mandatory.
// Damaged, foreign or contradictory records keep the launch closed.
func routedBootAttestationNextV4(kernel string, ids Identities, record, slot []byte, lineage string) ([]byte, bool, error) {
	boot, err := canonicalBoot([]byte(kernel))
	if err != nil || boot != kernel || ids.Validate() != nil || !retirementHashV3(lineage) || len(record) != RoutedScopeRecoveryRecordSizeV3 || len(slot) != RootRetirementReceiptSizeV3 {
		return nil, false, ErrIdentity
	}
	pinned := !bytes.Equal(record, make([]byte, len(record)))
	var previous RoutedScopeRecoveryRecordV3
	if pinned {
		if previous, err = DecodeRoutedScopeRecoveryV3(record); err != nil {
			return nil, false, ErrIdentity
		}
		if previous.Identities != ids || previous.Version == 4 && previous.LineageSHA256 != lineage {
			return nil, false, ErrIdentity
		}
	}
	var retired []RootBootAttestedScopeV4
	if routedSlotZeroV4(slot) {
		if !pinned {
			return nil, false, nil
		}
	} else if receipt, e := DecodeRootRetirementReceiptV3(slot); e == nil {
		if !pinned || receipt.Old == routedScopeRecordIdentityV4(previous) && receipt.MetadataSHA256 == previous.MetadataSHA256 {
			return nil, false, nil
		}
		if previous.PriorSlotSHA256 != retirementDigestV3(slot) || receipt.Old.BootID == kernel || receipt.Old.UID != ids.HelperUID || receipt.Old.GID != ids.IPCGID {
			return nil, false, ErrIdentity
		}
		retired = []RootBootAttestedScopeV4{{Old: receipt.Old, MetadataSHA256: receipt.MetadataSHA256, Source: routedBootAttestedReceiptV4, LineageSHA256: lineage, SourceSHA256: retirementDigestV3(slot)}}
	} else if earlier, e := DecodeRootBootAttestationV4(slot); e == nil {
		if earlier.Identities != ids || !earlier.matchesLineage(lineage) {
			return nil, false, ErrIdentity
		}
		for _, entry := range earlier.Retired {
			if entry.Old.BootID == kernel {
				return nil, false, ErrIdentity
			}
		}
		if !pinned && earlier.BootID == kernel {
			return nil, false, nil
		}
		retired = earlier.Retired
	} else {
		return nil, false, ErrIdentity
	}
	if pinned {
		if previous.Version != 4 {
			return nil, false, ErrIdentity
		}
		if previous.Metadata.BootID == kernel {
			return nil, false, nil // The exact orderly receipt remains mandatory to release this record.
		}
		old := routedScopeRecordIdentityV4(previous)
		next := []RootBootAttestedScopeV4{{Old: old, MetadataSHA256: previous.MetadataSHA256, Source: routedBootAttestedRecordV4, LineageSHA256: lineage, SourceSHA256: retirementDigestV3(record)}}
		for _, entry := range retired {
			if entry.Old != old && len(next) < routedBootAttestationLimitV4 {
				next = append(next, entry)
			}
		}
		retired = next
	}
	raw, err := EncodeRootBootAttestationV4(RootBootAttestationV4{Version: routedBootAttestationVersionV4, BootID: kernel, Identities: ids, Retired: retired})
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// routedBootAttestationReleasesV4 reports whether the slot attests exactly this
// persisted scope record for the running kernel boot.
func routedBootAttestationReleasesV4(kernel string, record, slot []byte) bool {
	previous, err := DecodeRoutedScopeRecoveryV3(record)
	if err != nil {
		return false
	}
	a, err := DecodeRootBootAttestationV4(slot)
	if err != nil || a.BootID != kernel || previous.Metadata.BootID == kernel || a.Identities != previous.Identities || previous.Version != 4 || !a.matchesLineage(previous.LineageSHA256) {
		return false
	}
	entry, ok := a.retired(routedScopeRecordIdentityV4(previous))
	return ok && entry.Source == routedBootAttestedRecordV4 && entry.MetadataSHA256 == previous.MetadataSHA256 && entry.SourceSHA256 == retirementDigestV3(record)
}

// routedRebootProofV4 is the root-authored content of the inherited slot under
// the OS reboot profile: an orderly drain receipt or a boot attestation.
type routedRebootProofV4 struct {
	receipt     *RootRetirementReceiptV3
	attestation *RootBootAttestationV4
}

type routedRetiredScopeV4 struct {
	metadata string
	drained  int64
	attested bool
}

func (p routedRebootProofV4) retired(old networkexecutor.OwnedNamespaceIdentity) (routedRetiredScopeV4, bool) {
	if p.receipt != nil && p.attestation == nil && p.receipt.Old == old {
		return routedRetiredScopeV4{metadata: p.receipt.MetadataSHA256, drained: p.receipt.DrainedAtBootNS}, true
	}
	if p.attestation != nil && p.receipt == nil {
		if entry, ok := p.attestation.retired(old); ok {
			return routedRetiredScopeV4{metadata: entry.MetadataSHA256, attested: true}, true
		}
	}
	return routedRetiredScopeV4{}, false
}

func (p routedRebootProofV4) identities() []networkexecutor.OwnedNamespaceIdentity {
	if p.receipt != nil && p.attestation == nil {
		return []networkexecutor.OwnedNamespaceIdentity{p.receipt.Old}
	}
	var out []networkexecutor.OwnedNamespaceIdentity
	if p.attestation != nil && p.receipt == nil {
		for _, entry := range p.attestation.Retired {
			out = append(out, entry.Old)
		}
	}
	return out
}

// decodeRoutedRebootProofV4 binds either slot content to the new scope. Every
// retired scope must belong to another boot, another run and the same accounts.
func decodeRoutedRebootProofV4(raw []byte, next networkexecutor.OwnedNamespaceIdentity, lineage string) (routedRebootProofV4, error) {
	if !retirementIdentityV3(next) {
		return routedRebootProofV4{}, ErrIdentity
	}
	if r, err := DecodeRootRetirementReceiptV3(raw); err == nil {
		if r.Old.BootID == next.BootID || r.Old.RunID == next.RunID || r.Old.UID != next.UID || r.Old.GID != next.GID {
			return routedRebootProofV4{}, ErrIdentity
		}
		return routedRebootProofV4{receipt: &r}, nil
	}
	a, err := DecodeRootBootAttestationV4(raw)
	if err != nil || a.BootID != next.BootID || a.Identities.HelperUID != next.UID || a.Identities.IPCGID != next.GID || !a.matchesLineage(lineage) {
		return routedRebootProofV4{}, ErrIdentity
	}
	for _, entry := range a.Retired {
		if entry.Old.BootID == next.BootID || entry.Old.RunID == next.RunID || entry.Old.UID != next.UID || entry.Old.GID != next.GID {
			return routedRebootProofV4{}, ErrIdentity
		}
	}
	return routedRebootProofV4{attestation: &a}, nil
}
