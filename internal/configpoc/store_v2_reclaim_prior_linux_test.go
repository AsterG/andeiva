//go:build linux

package configpoc

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

// This standalone adapter can also be copied into the preceding source tree
// when building the compatibility binary. It only calls that tree's openV2.
var priorReclaimArea = flag.String("prior-reclaim-area", "", "explicit compatibility fixture")

func TestReclaimPriorReader(t *testing.T) {
	if *priorReclaimArea == "" {
		t.Skip("prior-reader compatibility child only")
	}
	area, err := os.OpenRoot(*priorReclaimArea)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	store, err := openV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000})
	if err != nil {
		fmt.Println("OLD_READER_REJECTED")
		return
	}
	if err = store.close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("OLD_READER_ACCEPTED")
}
