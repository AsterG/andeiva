package previewruntime

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func retirementReceiptFixtureV3() RootRetirementReceiptV3 {
	return RootRetirementReceiptV3{Version: 3, Old: networkexecutor.OwnedNamespaceIdentity{UID: 62002, GID: 62003, Namespace: 42, Host: 40, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}, MetadataSHA256: strings.Repeat("b", 64), DrainedAtBootNS: 1000}
}

func TestRootRetirementReceiptV3FixedSizeAndIntegrity(t *testing.T) {
	r := retirementReceiptFixtureV3()
	raw, err := EncodeRootRetirementReceiptV3(r)
	if err != nil || len(raw) != RootRetirementReceiptSizeV3 {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeRootRetirementReceiptV3(raw)
	if err != nil || got.Old != r.Old || got.MetadataSHA256 != r.MetadataSHA256 || got.DrainedAtBootNS != r.DrainedAtBootNS || len(got.IntegritySHA256) != 64 {
		t.Fatalf("decode: %v", err)
	}
	for name, bad := range map[string][]byte{
		"empty-slot":    make([]byte, RootRetirementReceiptSizeV3),
		"truncated":     raw[:len(raw)-1],
		"appended":      append(append([]byte{}, raw...), ' '),
		"changed-body":  bytes.Replace(raw, []byte(`"drained_at_boot_ns":1000`), []byte(`"drained_at_boot_ns":1001`), 1),
		"padding-write": append(append([]byte{}, raw[:len(raw)-1]...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRootRetirementReceiptV3(bad); err == nil {
				t.Fatal("unproven receipt accepted")
			}
		})
	}
}

func TestRootRetirementReceiptV3RejectsUnprovenScope(t *testing.T) {
	for name, mutate := range map[string]func(*RootRetirementReceiptV3){
		"root-helper":   func(r *RootRetirementReceiptV3) { r.Old.UID = 0 },
		"host":          func(r *RootRetirementReceiptV3) { r.Old.Namespace = r.Old.Host },
		"zero-time":     func(r *RootRetirementReceiptV3) { r.DrainedAtBootNS = 0 },
		"caller-digest": func(r *RootRetirementReceiptV3) { r.IntegritySHA256 = strings.Repeat("c", 64) },
		"metadata":      func(r *RootRetirementReceiptV3) { r.MetadataSHA256 = "missing" },
		"run":           func(r *RootRetirementReceiptV3) { r.Old.RunID = strings.Repeat("A", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			r := retirementReceiptFixtureV3()
			mutate(&r)
			if _, err := EncodeRootRetirementReceiptV3(r); err == nil {
				t.Fatal("invalid receipt encoded")
			}
		})
	}
}
