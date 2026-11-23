package previewruntime

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const bootAttestationKernelV4 = "22345678-1234-1234-1234-123456789abc"

func bootLineageFixtureV5() routedBootLineageV5 {
	return routedBootLineageV5{Node: strings.Repeat("8", 32), DeploymentSHA256: strings.Repeat("9", 64), LinksSHA256: strings.Repeat("7", 64)}
}

func bootAttestationRecordV4(t *testing.T, mutate func(*RoutedScopeRecoveryRecordV3)) (RoutedScopeRecoveryRecordV3, []byte) {
	t.Helper()
	r := scopeRecoveryRecordFixtureV3()
	r.Version = 4
	r.LineageSHA256 = bootLineageFixtureV5().digest()
	r.PriorSlotSHA256 = retirementDigestV3(make([]byte, RootRetirementReceiptSizeV3))
	if mutate != nil {
		mutate(&r)
		r.MetadataSHA256 = retirementDigestV3(marshal(r.Metadata))
	}
	raw, err := EncodeRoutedScopeRecoveryV3(r)
	if err != nil {
		t.Fatal(err)
	}
	return r, raw
}

func bootAttestationIssueV4(t *testing.T, kernel string, ids Identities, record, slot []byte) RootBootAttestationV4 {
	t.Helper()
	raw, issue, err := routedBootAttestationNextV4(kernel, ids, record, slot, bootLineageFixtureV5().digest())
	if err != nil || !issue {
		t.Fatal("attestation was not issued", err)
	}
	a, err := DecodeRootBootAttestationV4(raw)
	if err != nil || a.BootID != kernel || a.Identities != ids {
		t.Fatal("issued attestation is not bound to the kernel boot and installation", err)
	}
	return a
}

func TestRoutedBootAttestationV4BindsRecordToANewKernelBoot(t *testing.T) {
	record, raw := bootAttestationRecordV4(t, nil)
	zero := make([]byte, RootRetirementReceiptSizeV3)
	a := bootAttestationIssueV4(t, bootAttestationKernelV4, record.Identities, raw, zero)
	old := routedScopeRecordIdentityV4(record)
	entry, ok := a.retired(old)
	if !ok || len(a.Retired) != 1 || entry.Source != routedBootAttestedRecordV4 || entry.MetadataSHA256 != record.MetadataSHA256 || entry.SourceSHA256 != retirementDigestV3(raw) {
		t.Fatal("attestation does not name the persisted scope record")
	}
	slot, err := EncodeRootBootAttestationV4(RootBootAttestationV4{Version: a.Version, BootID: a.BootID, Identities: a.Identities, Retired: a.Retired})
	if err != nil || !routedBootAttestationReleasesV4(bootAttestationKernelV4, raw, slot) {
		t.Fatal("exact attestation does not release its record", err)
	}
	// Repeating the launch after an interruption produces the same bytes.
	again, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, slot, bootLineageFixtureV5().digest())
	if err != nil || !issue || !bytes.Equal(again, slot) {
		t.Fatal("repeated attestation is not idempotent", err)
	}
	next := old
	next.BootID, next.RunID = bootAttestationKernelV4, strings.Repeat("b", 32)
	proof, err := decodeRoutedRebootProofV4(slot, next, bootLineageFixtureV5().digest())
	if err != nil || proof.receipt != nil || proof.attestation == nil {
		t.Fatal("helper did not accept the bound attestation", err)
	}
	retired, ok := proof.retired(old)
	if !ok || !retired.attested || retired.drained != 0 || retired.metadata != record.MetadataSHA256 {
		t.Fatal("attested scope claims a drain or another record")
	}
	unknown := old
	unknown.RunID = strings.Repeat("e", 32)
	if _, ok = proof.retired(unknown); ok {
		t.Fatal("unrecorded scope was covered by the attestation")
	}
}

func TestRoutedBootAttestationV4KeepsReceiptMandatoryForTheSameBoot(t *testing.T) {
	record, raw := bootAttestationRecordV4(t, nil)
	zero := make([]byte, RootRetirementReceiptSizeV3)
	// The record belongs to the running kernel: this is a service restart.
	next, issue, err := routedBootAttestationNextV4(record.Metadata.BootID, record.Identities, raw, zero, bootLineageFixtureV5().digest())
	if err != nil || issue || next != nil {
		t.Fatal("same-boot record produced an attestation", err)
	}
	a := bootAttestationIssueV4(t, bootAttestationKernelV4, record.Identities, raw, zero)
	slot, err := EncodeRootBootAttestationV4(RootBootAttestationV4{Version: a.Version, BootID: a.BootID, Identities: a.Identities, Retired: a.Retired})
	if err != nil {
		t.Fatal(err)
	}
	if routedBootAttestationReleasesV4(record.Metadata.BootID, raw, slot) {
		t.Fatal("record of the running boot was released without a drain receipt")
	}
	// An attestation issued by an earlier boot is not valid for a later scope
	// until root issues it again from the kernel identity it reads itself.
	later := routedScopeRecordIdentityV4(record)
	later.BootID, later.RunID = "32345678-1234-1234-1234-123456789abc", strings.Repeat("b", 32)
	if _, err = decodeRoutedRebootProofV4(slot, later, bootLineageFixtureV5().digest()); !errors.Is(err, ErrIdentity) {
		t.Fatal("attestation of another kernel boot was accepted", err)
	}
	same := routedScopeRecordIdentityV4(record)
	same.RunID = strings.Repeat("b", 32)
	if _, err = decodeRoutedRebootProofV4(slot, same, bootLineageFixtureV5().digest()); !errors.Is(err, ErrIdentity) {
		t.Fatal("attestation was accepted for the boot of the retired scope", err)
	}
}

func TestRoutedBootAttestationV4RejectsForeignTamperedAndDamagedRecords(t *testing.T) {
	record, raw := bootAttestationRecordV4(t, nil)
	zero := make([]byte, RootRetirementReceiptSizeV3)
	foreign := record.Identities
	foreign.HelperUID++
	tampered := append([]byte{}, raw...)
	tampered[bytes.Index(tampered, []byte(record.Metadata.RunID))] = 'f'
	torn := append([]byte{}, raw...)
	copy(torn[2048:], make([]byte, 2048))
	a := bootAttestationIssueV4(t, bootAttestationKernelV4, record.Identities, raw, zero)
	slot, err := EncodeRootBootAttestationV4(RootBootAttestationV4{Version: a.Version, BootID: a.BootID, Identities: a.Identities, Retired: a.Retired})
	if err != nil {
		t.Fatal(err)
	}
	damagedSlot := append([]byte{}, slot...)
	damagedSlot[bytes.Index(damagedSlot, []byte(record.Metadata.RunID))] = 'f'
	foreignScope := a.Retired[0]
	foreignScope.Old.UID = foreign.HelperUID
	otherInstallation, err := EncodeRootBootAttestationV4(RootBootAttestationV4{Version: routedBootAttestationVersionV4, BootID: a.BootID, Identities: foreign, Retired: []RootBootAttestedScopeV4{foreignScope}})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kernel       string
		ids          Identities
		record, slot []byte
	}{
		"record of another installation":      {bootAttestationKernelV4, foreign, raw, zero},
		"tampered record":                     {bootAttestationKernelV4, record.Identities, tampered, zero},
		"torn record":                         {bootAttestationKernelV4, record.Identities, torn, zero},
		"damaged slot":                        {bootAttestationKernelV4, record.Identities, raw, damagedSlot},
		"attestation of another installation": {bootAttestationKernelV4, record.Identities, raw, otherInstallation},
		"noncanonical kernel identity":        {strings.ToUpper(bootAttestationKernelV4), record.Identities, raw, zero},
		"short record":                        {bootAttestationKernelV4, record.Identities, raw[:100], zero},
	} {
		t.Run(name, func(t *testing.T) {
			next, issue, err := routedBootAttestationNextV4(c.kernel, c.ids, c.record, c.slot, bootLineageFixtureV5().digest())
			if !errors.Is(err, ErrIdentity) || issue || next != nil {
				t.Fatal("launch was not kept closed", err)
			}
		})
	}
	if routedBootAttestationReleasesV4(bootAttestationKernelV4, tampered, slot) || routedBootAttestationReleasesV4(bootAttestationKernelV4, raw, damagedSlot) || routedBootAttestationReleasesV4(bootAttestationKernelV4, raw, otherInstallation) {
		t.Fatal("tampered or foreign proof released the scope record")
	}
	// Another record of the same installation is not the attested one.
	_, sibling := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) { r.Metadata.RunID = strings.Repeat("d", 32) })
	if routedBootAttestationReleasesV4(bootAttestationKernelV4, sibling, slot) {
		t.Fatal("attestation released a record it does not name")
	}
	if _, err = DecodeRootBootAttestationV4(damagedSlot); !errors.Is(err, ErrIdentity) {
		t.Fatal("damaged attestation decoded", err)
	}
	if _, err = DecodeRootBootAttestationV4(slot[:len(slot)-1]); !errors.Is(err, ErrIdentity) {
		t.Fatal("truncated attestation decoded", err)
	}
}

func TestRoutedBootAttestationV4KeepsOrderlyReceiptPath(t *testing.T) {
	record, raw := bootAttestationRecordV4(t, nil)
	old := routedScopeRecordIdentityV4(record)
	orderly, err := EncodeRootRetirementReceiptV3(RootRetirementReceiptV3{Version: 3, Old: old, MetadataSHA256: record.MetadataSHA256, DrainedAtBootNS: 7})
	if err != nil {
		t.Fatal(err)
	}
	// Power was lost after the drain receipt and before the record was cleared.
	next, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, orderly, bootLineageFixtureV5().digest())
	if err != nil || issue || next != nil {
		t.Fatal("orderly receipt was replaced by an attestation", err)
	}
	zeroRecord := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	if next, issue, err = routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, zeroRecord, orderly, bootLineageFixtureV5().digest()); err != nil || issue || next != nil {
		t.Fatal("receipt without a pending record was replaced", err)
	}
	if next, issue, err = routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, zeroRecord, make([]byte, RootRetirementReceiptSizeV3), bootLineageFixtureV5().digest()); err != nil || issue || next != nil {
		t.Fatal("first activation produced an attestation", err)
	}
	// A receipt of an earlier scope stays attributable after the power loss.
	stale := old
	stale.RunID = strings.Repeat("9", 32)
	staleRaw, err := EncodeRootRetirementReceiptV3(RootRetirementReceiptV3{Version: 3, Old: stale, MetadataSHA256: strings.Repeat("b", 64), DrainedAtBootNS: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, staleRaw, bootLineageFixtureV5().digest()); !errors.Is(err, ErrIdentity) || issue {
		t.Fatal("an unrelated receipt entered the attestation", err)
	}
	_, anchored := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) {
		r.PriorSlotSHA256 = retirementDigestV3(staleRaw)
	})
	a := bootAttestationIssueV4(t, bootAttestationKernelV4, record.Identities, anchored, staleRaw)
	if len(a.Retired) != 2 || a.Retired[0].Old != old || a.Retired[1].Old != stale || a.Retired[1].Source != routedBootAttestedReceiptV4 || a.Retired[1].SourceSHA256 != retirementDigestV3(staleRaw) {
		t.Fatal("earlier drained scope was not retained")
	}
	current := stale
	current.BootID = bootAttestationKernelV4
	currentRaw, err := EncodeRootRetirementReceiptV3(RootRetirementReceiptV3{Version: 3, Old: current, MetadataSHA256: strings.Repeat("b", 64), DrainedAtBootNS: 5})
	if err != nil {
		t.Fatal(err)
	}
	if next, issue, err = routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, currentRaw, bootLineageFixtureV5().digest()); !errors.Is(err, ErrIdentity) || issue || next != nil {
		t.Fatal("contradictory receipt of the running boot was accepted", err)
	}
}

// Power may be lost again at any point of the recovery. The selected store can
// then still name the first scope or already the interrupted replacement, so
// root keeps every scope it recorded until an orderly drain replaces the slot.
func TestRoutedBootAttestationV4AccumulatesRepeatedPowerLoss(t *testing.T) {
	ids := scopeRecoveryRecordFixtureV3().Identities
	slot := make([]byte, RootRetirementReceiptSizeV3)
	zeroRecord := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	var boots []string
	for i := 0; i < routedBootAttestationLimitV4+3; i++ {
		record, raw := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) {
			r.Metadata.BootID = fmt.Sprintf("%08x-1234-1234-1234-123456789abc", 0x40000000+i)
			r.Metadata.RunID = fmt.Sprintf("%032x", i+1)
		})
		boots = append(boots, record.Metadata.BootID)
		kernel := fmt.Sprintf("%08x-1234-1234-1234-123456789abc", 0x40000000+i+1)
		a := bootAttestationIssueV4(t, kernel, ids, raw, slot)
		want := min(i+1, routedBootAttestationLimitV4)
		if len(a.Retired) != want || a.Retired[0].Old.BootID != record.Metadata.BootID {
			t.Fatal("newest recorded scope is not first or the bound was exceeded", len(a.Retired))
		}
		for j, entry := range a.Retired {
			if entry.Old.BootID != boots[i-j] {
				t.Fatal("retired scopes are not ordered from newest to oldest")
			}
		}
		var err error
		if slot, err = EncodeRootBootAttestationV4(RootBootAttestationV4{Version: a.Version, BootID: a.BootID, Identities: a.Identities, Retired: a.Retired}); err != nil {
			t.Fatal(err)
		}
		if !routedBootAttestationReleasesV4(kernel, raw, slot) {
			t.Fatal("record was not released by its attestation")
		}
		// Interrupted after the record was cleared: nothing changes on the same boot.
		if next, issue, e := routedBootAttestationNextV4(kernel, ids, zeroRecord, slot, bootLineageFixtureV5().digest()); e != nil || issue || next != nil {
			t.Fatal("cleared record changed the attestation on the same boot", e)
		}
	}
	// A further boot with no new record issues the same list for its own identity.
	final := "7f345678-1234-1234-1234-123456789abc"
	before, err := DecodeRootBootAttestationV4(slot)
	if err != nil {
		t.Fatal(err)
	}
	a := bootAttestationIssueV4(t, final, ids, zeroRecord, slot)
	if len(a.Retired) != len(before.Retired) {
		t.Fatal("reissued attestation changed the retired scopes")
	}
	for i := range a.Retired {
		if a.Retired[i] != before.Retired[i] {
			t.Fatal("reissued attestation changed a retired scope")
		}
	}
}

func TestRoutedBootAttestationV5RequiresLocalLineage(t *testing.T) {
	lineage := bootLineageFixtureV5()
	digest := lineage.digest()
	zero := make([]byte, RootRetirementReceiptSizeV3)
	for name, change := range map[string]func(*routedBootLineageV5){
		"foreign node with the same accounts": func(l *routedBootLineageV5) { l.Node = strings.Repeat("1", 32) },
		"foreign provisioning origin":         func(l *routedBootLineageV5) { l.DeploymentSHA256 = strings.Repeat("2", 64) },
		"foreign link manifest":               func(l *routedBootLineageV5) { l.LinksSHA256 = strings.Repeat("3", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := lineage
			change(&foreign)
			record, raw := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) {
				r.LineageSHA256 = foreign.digest()
			})
			if next, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, zero, digest); !errors.Is(err, ErrIdentity) || issue || next != nil {
				t.Fatal("foreign root record accepted", err)
			}
			slot, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, zero, foreign.digest())
			if err != nil || !issue {
				t.Fatal("fixture did not produce a foreign attestation", err)
			}
			next := routedScopeRecordIdentityV4(record)
			next.BootID, next.RunID = bootAttestationKernelV4, strings.Repeat("3", 32)
			if _, err = decodeRoutedRebootProofV4(slot, next, digest); !errors.Is(err, ErrIdentity) {
				t.Fatal("helper accepted a foreign attestation", err)
			}
		})
	}
}

func TestRoutedBootAttestationV5LegacyRequiresExactDrain(t *testing.T) {
	record := scopeRecoveryRecordFixtureV3()
	raw, err := EncodeRoutedScopeRecoveryV3(record)
	if err != nil {
		t.Fatal(err)
	}
	old := routedScopeRecordIdentityV4(record)
	receipt := RootRetirementReceiptV3{Version: 3, Old: old, MetadataSHA256: record.MetadataSHA256, DrainedAtBootNS: 7}
	exact, err := EncodeRootRetirementReceiptV3(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Old.RunID = strings.Repeat("9", 32)
	inexact, err := EncodeRootRetirementReceiptV3(receipt)
	if err != nil {
		t.Fatal(err)
	}
	digest := bootLineageFixtureV5().digest()
	for name, slot := range map[string][]byte{
		"no receipt":      make([]byte, RootRetirementReceiptSizeV3),
		"inexact receipt": inexact,
	} {
		t.Run(name, func(t *testing.T) {
			if next, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, slot, digest); !errors.Is(err, ErrIdentity) || issue || next != nil {
				t.Fatal("unbound record accepted without its exact receipt", err)
			}
		})
	}
	if next, issue, err := routedBootAttestationNextV4(bootAttestationKernelV4, record.Identities, raw, exact, digest); err != nil || issue || next != nil {
		t.Fatal("exact orderly receipt did not preserve the legacy path", err)
	}
	next := old
	next.BootID, next.RunID = bootAttestationKernelV4, strings.Repeat("3", 32)
	proof, err := decodeRoutedRebootProofV4(exact, next, "")
	if err != nil || proof.receipt == nil || proof.receipt.Old != old {
		t.Fatal("helper refused the original receipt format", err)
	}
}
