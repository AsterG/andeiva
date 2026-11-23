//go:build linux

package previewruntime

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// Real root-owned slots on a private directory. The kernel identity is the one
// of the machine running the test; no systemd, namespace or network is used.
func bootAttestationSlotsV4(t *testing.T) (*os.Root, *routedRetirementSlot, *routedScopeRecordSlotV3) {
	t.Helper()
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("requires root-owned operational slots")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = area.Close() })
	slot, err := openRoutedRetirementSlotV3(area)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slot.Close() })
	record, err := openScopeRecordSlotV3(area, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = record.Close() })
	return area, slot, record
}

func TestRoutedBootAttestationV4RootWritesItFromThePersistedRecord(t *testing.T) {
	area, slot, record := bootAttestationSlotsV4(t)
	kernel, err := readRoutedKernelBootID()
	if err != nil {
		t.Fatal(err)
	}
	previous, raw := bootAttestationRecordV4(t, nil)
	if previous.Metadata.BootID == kernel {
		t.Fatal("fixture boot identity collides with the running kernel")
	}
	if err = record.publish(raw); err != nil {
		t.Fatal(err)
	}
	if err = attestRoutedBootV4(slot, record, previous.Identities, bootLineageFixtureV5().digest()); err != nil {
		t.Fatal(err)
	}
	written, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeRootBootAttestationV4(written)
	old := routedScopeRecordIdentityV4(previous)
	if err != nil || a.BootID != kernel || len(a.Retired) != 1 || a.Retired[0].Old != old || !routedBootAttestationReleasesV4(kernel, raw, written) {
		t.Fatal("slot does not attest the persisted record for the running kernel", err)
	}
	// An interrupted launch repeats the same step without changing the slot.
	if err = attestRoutedBootV4(slot, record, previous.Identities, bootLineageFixtureV5().digest()); err != nil {
		t.Fatal(err)
	}
	again, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil || !bytes.Equal(written, again) {
		t.Fatal("repeated attestation changed the slot", err)
	}
	// The helper receives a read-only descriptor bound by digest to the new scope.
	file, err := area.OpenFile(routedRetirementSlotV3, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	next := old
	next.BootID, next.RunID = kernel, strings.Repeat("b", 32)
	binding := RoutedRebootScopeBindingV4{ReceiptSHA256: retirementDigestV3(written), NewIdentity: next, Lineage: new(bootLineageFixtureV5())}
	proof, err := readRebootRetirementFileV4(file, binding)
	if err != nil || proof.attestation == nil {
		t.Fatal("helper refused the attested slot", err)
	}
	if retired, ok := proof.retired(old); !ok || !retired.attested || retired.drained != 0 {
		t.Fatal("helper did not find the recorded scope")
	}
	p := &routedFreshScopeV3{file: file, binding: RoutedFreshScopeBindingV3{ReceiptSHA256: binding.ReceiptSHA256, NewIdentity: next}, rebootBinding: binding, reboot: true}
	if _, err = p.readReceipt(); err != nil {
		t.Fatal("helper proof refused the running kernel", err)
	}
	for name, lineage := range map[string]*routedBootLineageV5{
		"missing": nil,
		"foreign": {Node: strings.Repeat("2", 32), DeploymentSHA256: binding.Lineage.DeploymentSHA256, LinksSHA256: binding.Lineage.LinksSHA256},
	} {
		t.Run(name, func(t *testing.T) {
			ref := binding
			ref.Lineage = lineage
			bootstrap := routedLaunchBootstrapV3{Integrity: true, RebootScope: true, RebootScopeBinding: &ref}
			if err := validateRoutedScopeReceiptV4(file, bootstrap); !errors.Is(err, ErrIdentity) {
				t.Fatal("helper accepted invalid bootstrap lineage", err)
			}
		})
	}
	stale := binding
	stale.NewIdentity.BootID = "32345678-1234-1234-1234-123456789abc"
	if _, err = readRebootRetirementFileV4(file, stale); !errors.Is(err, ErrIdentity) {
		t.Fatal("attestation accepted for a scope of another kernel boot", err)
	}
	wrong := binding
	wrong.ReceiptSHA256 = strings.Repeat("c", 64)
	if _, err = readRebootRetirementFileV4(file, wrong); !errors.Is(err, ErrIdentity) {
		t.Fatal("attestation accepted under another digest", err)
	}
	// The slot still reopens, and an orderly drain later replaces it.
	if err = slot.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openRoutedRetirementSlotV3(area)
	if err != nil {
		t.Fatal("attested slot was not adopted", err)
	}
	defer reopened.Close()
	m := previous.Metadata
	m.BootID, m.RunID = kernel, strings.Repeat("b", 32)
	if err = reopened.recordDrained(m, previous.Identities); err != nil {
		t.Fatal(err)
	}
	drained, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRootRetirementReceiptV3(drained); err != nil {
		t.Fatal("orderly receipt did not replace the attestation", err)
	}
}

func TestRoutedBootAttestationV4RootKeepsTheSameBootClosed(t *testing.T) {
	area, slot, record := bootAttestationSlotsV4(t)
	kernel, err := readRoutedKernelBootID()
	if err != nil {
		t.Fatal(err)
	}
	// The recorded scope belongs to the running kernel: a service restart.
	previous, raw := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) { r.Metadata.BootID = kernel })
	if err = record.publish(raw); err != nil {
		t.Fatal(err)
	}
	if err = attestRoutedBootV4(slot, record, previous.Identities, bootLineageFixtureV5().digest()); err != nil {
		t.Fatal(err)
	}
	written, err := area.ReadFile(routedRetirementSlotV3)
	if err != nil || !routedSlotZeroV4(written) {
		t.Fatal("same-boot restart wrote an attestation", err)
	}
	if routedBootAttestationReleasesV4(kernel, raw, written) {
		t.Fatal("same-boot record released without a drain receipt")
	}
}

func TestRoutedBootAttestationV4RootRejectsForeignAndDamagedRecords(t *testing.T) {
	for _, scenario := range []string{"foreign_accounts", "foreign_node", "foreign_origin", "damaged"} {
		t.Run(scenario, func(t *testing.T) {
			area, slot, record := bootAttestationSlotsV4(t)
			previous, raw := bootAttestationRecordV4(t, func(r *RoutedScopeRecoveryRecordV3) {
				lineage := bootLineageFixtureV5()
				switch scenario {
				case "foreign_node":
					lineage.Node = strings.Repeat("1", 32)
				case "foreign_origin":
					lineage.DeploymentSHA256 = strings.Repeat("2", 64)
				}
				r.LineageSHA256 = lineage.digest()
			})
			ids := previous.Identities
			if scenario == "foreign_accounts" {
				ids.HelperUID++
			}
			if scenario == "damaged" {
				damaged := append([]byte{}, raw...)
				damaged[bytes.Index(damaged, []byte(previous.Metadata.RunID))] = 'f'
				raw = damaged
				if err := record.write(raw); err != nil {
					t.Fatal(err)
				}
			} else if err := record.publish(raw); err != nil {
				t.Fatal(err)
			}
			if err := attestRoutedBootV4(slot, record, ids, bootLineageFixtureV5().digest()); err == nil {
				t.Fatal("launch continued with an unusable scope record")
			}
			written, err := area.ReadFile(routedRetirementSlotV3)
			if err != nil || !routedSlotZeroV4(written) {
				t.Fatal("rejected record changed the slot", err)
			}
			after, err := record.read()
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("rejection changed the original scope record", err)
			}
		})
	}
}
