//go:build linux

package configpoc

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

var priorDHCPConfigurationArea = flag.String("prior-dhcp-configuration-area", "", "explicit shared-store compatibility fixture")

// Test-only adapter. All record decoding and feature checks are performed by
// the unmodified historical commit's shared store reader.
func TestDHCPConfigurationPriorReader(t *testing.T) {
	if *priorDHCPConfigurationArea == "" {
		t.Skip("prior-reader child only")
	}
	area, err := os.OpenRoot(*priorDHCPConfigurationArea)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	info, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing directory provenance")
	}
	access := recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: st.Uid, ReaderGID: st.Gid, Device: st.Dev, Inode: st.Ino}
	store, err := openSharedStoreV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000}, access)
	if err != nil {
		fmt.Println("OLD_READER_REJECTED")
		return
	}
	if err = store.close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("OLD_READER_ACCEPTED")
}
