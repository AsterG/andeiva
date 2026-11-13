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

// This standalone adapter is compiled against the preceding production source.
// It supports that source's existing private and shared readers; rejection must
// not merely be the private reader rejecting a shared filesystem profile.
var offlineMigrationPriorAreaV3 = flag.String("offline-migration-prior-area", "", "explicit offline migration compatibility fixture")

func TestOfflineMigrationPriorReaderV3(t *testing.T) {
	if *offlineMigrationPriorAreaV3 == "" {
		t.Skip("prior-source compatibility child only")
	}
	area, err := os.OpenRoot(*offlineMigrationPriorAreaV3)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	info, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	var s *v2Store
	budget := v2Budget{Bytes: 8 << 30, Inodes: 2 << 20}
	if info.Mode().Perm() == 0700 {
		s, err = openV2(area, budget)
	} else {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("no filesystem identity")
		}
		s, err = openSharedStoreV2(area, budget, recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: stat.Uid, ReaderGID: stat.Gid, Device: stat.Dev, Inode: stat.Ino})
	}
	if err != nil {
		fmt.Println("PRIOR_MIGRATION_REJECTED")
		return
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("PRIOR_MIGRATION_ACCEPTED")
}
