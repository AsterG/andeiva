package previewruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const RootRetirementReceiptSizeV3 = 4096

type routedFreshScopeProofV3 interface {
	configpoc.RoutedFreshScopeAuthorityV3
	prepareSelected(context.Context, configpoc.RoutedActivationBundleV1, string) (configpoc.RoutedPreparationV1, error)
	verifyPlan(context.Context, configpoc.RoutedSelectedPlanV1) error
	Close() error
}

func freshScopeAllowedV3(g *routedIntegrityGateV3) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fence != nil && !g.blockedLocked() && g.anchor != (configpoc.SelectionReferenceV2{}) && (g.phase == routedIntegrityReconcilingV3 || g.phase == routedIntegrityReadyV3)
}

// RootRetirementReceiptV3 is an operational supervisor receipt, never a
// configuration request. Root writes the preallocated slot only after all
// children have been waited for and the old namespace pin has been closed.
// Its digest detects a torn write; root ownership and inherited FD provenance,
// rather than the digest, establish who is allowed to issue it.
type RootRetirementReceiptV3 struct {
	Version         int                                    `json:"version"`
	Old             networkexecutor.OwnedNamespaceIdentity `json:"old"`
	MetadataSHA256  string                                 `json:"metadata_sha256"`
	DrainedAtBootNS int64                                  `json:"drained_at_boot_ns"`
	IntegritySHA256 string                                 `json:"integrity_sha256,omitempty"`
}

// RoutedFreshScopeBindingV3 comes from the root-authenticated bootstrap. The
// full fixed-size file digest includes padding; it binds this receipt to exactly
// one newly constructed run/namespace. Neither field is accepted over API IPC.
type RoutedFreshScopeBindingV3 struct {
	ReceiptSHA256 string
	NewIdentity   networkexecutor.OwnedNamespaceIdentity
}

func retirementIdentityV3(id networkexecutor.OwnedNamespaceIdentity) bool {
	boot, err := canonicalBoot([]byte(id.BootID))
	return err == nil && boot == id.BootID && ValidRun(id.RunID) && id.UID != 0 && id.GID != 0 && id.Namespace != 0 && id.Host != 0 && id.Namespace != id.Host
}

func retirementHashV3(hash string) bool {
	if len(hash) != 64 || strings.ToLower(hash) != hash {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func retirementDigestV3(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// EncodeRootRetirementReceiptV3 returns exactly 4096 bytes, canonical JSON
// followed by spaces. The writer must write all bytes in place and fsync; this
// pure codec does not claim that retirement happened or write a file.
func EncodeRootRetirementReceiptV3(receipt RootRetirementReceiptV3) ([]byte, error) {
	if receipt.Version != 3 || !retirementIdentityV3(receipt.Old) || !retirementHashV3(receipt.MetadataSHA256) || receipt.DrainedAtBootNS <= 0 || receipt.IntegritySHA256 != "" {
		return nil, ErrIdentity
	}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return nil, ErrIdentity
	}
	receipt.IntegritySHA256 = retirementDigestV3(unsigned)
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > RootRetirementReceiptSizeV3 {
		return nil, ErrIdentity
	}
	return append(raw, bytes.Repeat([]byte{' '}, RootRetirementReceiptSizeV3-len(raw))...), nil
}

// DecodeRootRetirementReceiptV3 accepts only the exact encoding emitted above.
// A zero/preallocated, partial, reordered, duplicate-field or damaged slot is
// not a receipt. This validates bytes, not root ownership or process drainage.
func DecodeRootRetirementReceiptV3(raw []byte) (RootRetirementReceiptV3, error) {
	var receipt RootRetirementReceiptV3
	if len(raw) != RootRetirementReceiptSizeV3 {
		return receipt, ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || !retirementHashV3(receipt.IntegritySHA256) {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	unsigned := receipt
	unsigned.IntegritySHA256 = ""
	expected, err := EncodeRootRetirementReceiptV3(unsigned)
	if err != nil || !bytes.Equal(raw, expected) {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	return receipt, nil
}
