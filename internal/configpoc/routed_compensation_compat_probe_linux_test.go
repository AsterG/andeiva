//go:build linux

package configpoc

import (
	"flag"
	"os"
	"syscall"
	"testing"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

var compensationProbeArea = flag.String("compensation-probe-area", "", "shared fixture directory for the prior-reader probe")

// This adapter compiles with the prior source unchanged. It calls that
// revision's own shared store opener with the fixture's actual access profile.
func TestCompensationCompatibilityProbe(t *testing.T) {
	if *compensationProbeArea == "" {
		t.Skip("standalone prior-reader adapter")
	}
	area, err := os.OpenRoot(*compensationProbeArea)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	info, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	access := recoveryreserve.ReaderAccessV2{
		Version: 1, OwnerUID: stat.Uid, ReaderGID: stat.Gid, Device: uint64(stat.Dev), Inode: stat.Ino,
	}
	store, err := openSharedStoreV2(area, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20}, access)
	if err != nil {
		t.Log("COMPENSATION_READER_REJECTED")
		return
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	t.Log("COMPENSATION_READER_ACCEPTED")
}
