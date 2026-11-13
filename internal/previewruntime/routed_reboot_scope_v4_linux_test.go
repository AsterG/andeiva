package previewruntime

import (
	"os"
	"testing"
)

func TestRoutedRebootScopeV4RejectsWritableAndTruncatedReceipt(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := retirementReceiptFixtureV3()
	raw, err := EncodeRootRetirementReceiptV3(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		t.Fatal(err)
	}
	next := r.Old
	next.BootID = "22345678-1234-1234-1234-123456789abc"
	next.RunID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	binding := RoutedRebootScopeBindingV4{ReceiptSHA256: retirementDigestV3(raw), NewIdentity: next}
	if _, err = readRebootRetirementFileV4(f, binding); err == nil {
		t.Fatal("writable receipt accepted")
	}
	if err = f.Truncate(100); err != nil {
		t.Fatal(err)
	}
	read, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if _, err = readRebootRetirementFileV4(read, binding); err == nil {
		t.Fatal("truncated receipt accepted")
	}
}
