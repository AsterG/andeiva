package previewruntime

import (
	"os"
	"testing"
)

func TestRoutedFreshScopeV3RejectsWritableAndIncompleteReceiptFD(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeRootRetirementReceiptV3(retirementReceiptFixtureV3())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(raw); err != nil {
		t.Fatal(err)
	}
	if validateRetirementFileV3(file) == nil {
		t.Fatal("writable inherited receipt accepted")
	}
	if validateRetirementFileV3(nil) == nil {
		t.Fatal("absent descriptor accepted")
	}
	if err = file.Truncate(100); err != nil {
		t.Fatal(err)
	}
	read, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if validateRetirementFileV3(read) == nil {
		t.Fatal("partial receipt slot accepted")
	}
}

func TestRoutedFreshScopeV3AbsenceRejectsEveryNFTTable(t *testing.T) {
	for _, raw := range []string{`{"nftables":[]}`, `{"nftables":[{"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}}]}`} {
		if err := freshScopeEmptyTablesV3([]byte(raw)); err != nil {
			t.Fatal("empty listing", err)
		}
	}
	for _, raw := range []string{`{}`, `{"nftables":[{"table":{"family":"inet","name":"andeiva_lease_gate"}}]}`, `{"nftables":[{"table":{"family":"ip6","name":"foreign"}}]}`, `{"nftables":[],"nftables":[]}`} {
		if freshScopeEmptyTablesV3([]byte(raw)) == nil {
			t.Fatal("unproven empty namespace", raw)
		}
	}
}
