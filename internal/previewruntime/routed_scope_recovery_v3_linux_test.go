//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestRoutedScopeRecoveryV3RefusesUnprivilegedConstruction(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("capless negative")
	}
	r := scopeRecoveryRecordFixtureV3()
	if _, err := PrepareRoutedScopeRecoveryRecordV3(context.Background(), r.Metadata, r.Identities, RoutedScopeRecoveryAnchorsV3{}); err == nil {
		t.Fatal("unprivileged capture")
	}
	if _, err := OpenRoutedScopeRecoveryV3(context.Background(), RoutedScopeRecoveryAnchorsV3{}); err == nil {
		t.Fatal("unprivileged recovery")
	}
	if err := (&RoutedScopeRecoveryV3{}).VerifyStored(context.Background()); err == nil {
		t.Fatal("unprivileged store inspection")
	}
}
func TestRoutedScopeRecoveryV3StoreReadbackRequiresExactAllDescriptors(t *testing.T) {
	expected := map[string]scopeRecoveryStoredV3{}
	entries := [][]any{}
	for i, name := range scopeRecoveryNamesV3 {
		v := scopeRecoveryStoredV3{Mode: 0100600, Major: 1, Minor: 2, Inode: uint64(i + 10), Flags: 0}
		expected[name] = v
		entries = append(entries, []any{name, v.Mode, v.Major, v.Minor, v.Inode, v.Rmajor, v.Rminor, "ignored-path", v.Flags})
	}
	encode := func(entries [][]any) []byte {
		raw, err := json.Marshal(struct {
			Type string `json:"type"`
			Data any    `json:"data"`
		}{"a(suuutuusu)", []any{entries}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !scopeRecoveryStoreMatchesV3(encode(entries), expected) {
		t.Fatal("exact store refused")
	}
	entries[0], entries[5] = entries[5], entries[0]
	if !scopeRecoveryStoreMatchesV3(encode(entries), expected) {
		t.Fatal("unordered store refused")
	}
	for name, mutate := range map[string]func([][]any) [][]any{
		"missing":     func(e [][]any) [][]any { return e[:5] },
		"duplicate":   func(e [][]any) [][]any { e[1] = e[0]; return e },
		"foreign":     func(e [][]any) [][]any { e[0][0] = "foreign"; return e },
		"inode":       func(e [][]any) [][]any { e[0][4] = uint64(999); return e },
		"writable":    func(e [][]any) [][]any { e[0][8] = 2; return e },
		"device":      func(e [][]any) [][]any { e[0][2] = 99; return e },
		"null_flags":  func(e [][]any) [][]any { e[0][8] = nil; return e },
		"extra_field": func(e [][]any) [][]any { e[0] = append(e[0], "extra"); return e },
	} {
		t.Run(name, func(t *testing.T) {
			copy := make([][]any, len(entries))
			for i, e := range entries {
				copy[i] = append([]any{}, e...)
			}
			if scopeRecoveryStoreMatchesV3(encode(mutate(copy)), expected) {
				t.Fatal("invalid manager readback accepted")
			}
		})
	}
}

func TestRoutedScopeRecoveryV3RejectsWritableAndWrongDescriptorType(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "record")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := scopeRecoveryIdentityV3(f); err == nil {
		t.Fatal("writable anchor accepted")
	}
	readonly, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	if scopeRecoveryNamespaceV3(readonly, 0x40000000) {
		t.Fatal("regular file accepted as network namespace")
	}
	if validateScopeRecoveryRecordFileV3(readonly) == nil {
		t.Fatal("unallocated record accepted")
	}
}
