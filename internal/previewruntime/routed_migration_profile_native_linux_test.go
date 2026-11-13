//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"
	"time"
)

var migrationProfileNativeV3 = flag.Bool("andeiva-native-migration-profile-v3", false, "explicit root conversion of a fresh authorized prepared store")
var migrationProfileFaultsNativeV3 = flag.Bool("andeiva-native-migration-profile-faults-v3", false, "explicit root temporary permission-conversion fault fixtures")

func profileNativeIdentitiesV3(t *testing.T) (Config, Identities, uint32) {
	t.Helper()
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root installer required")
	}
	c, e := LoadConfig(ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	ids, e := LoadIdentities(c)
	if e != nil {
		t.Fatal(e)
	}
	registry, e := readOwned(routedReaderRegistryPathV3, 0, 0, 0600, 4096)
	if e != nil {
		t.Fatal(e)
	}
	groups, e := readOwned("/etc/group", 0, 0, 0644, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	gid, e := readerGroupFromV3(registry, groups, ids)
	if e != nil {
		t.Fatal(e)
	}
	return c, ids, gid
}
func TestRoutedMigrationProfileNativeV3(t *testing.T) {
	if !*migrationProfileNativeV3 {
		t.Skip("requires fresh prepared destination, versioned exclusive reader group and stopped API/socket")
	}
	c, _, _ := profileNativeIdentitiesV3(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	before, e := InspectRoutedMigrationV3(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	result, e := ConvertRoutedMigrationProfileV3(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if result.Version != 1 || result.PlanSHA256 != before.PlanSHA256 {
		t.Fatal("invalid profile correlation")
	}
	after, e := InspectRoutedMigrationV3(ctx, c)
	if e != nil || after.Firewall != before.Firewall || after.PlanSHA256 != before.PlanSHA256 {
		t.Fatal("original history/accounts changed", e)
	}
	t.Log("PASS: actual root conversion with retained locks, preserved API ownership and exact hashes; original FW/accounts unchanged. Metadata only: no root G1, engine, new gateway, activation or readiness claim")
}
func TestRoutedMigrationProfileFaultsNativeV3(t *testing.T) {
	if !*migrationProfileFaultsNativeV3 {
		t.Skip("requires explicit root temporary filesystem fault qualification")
	}
	_, ids, gid := profileNativeIdentitiesV3(t)
	for _, point := range []string{"complete", "after_file:0:checkpoint.lock", "after_directory:0", "swap-before-file"} {
		t.Run(point, func(t *testing.T) {
			// These byte fixtures are NOT valid selected policies or G1. Actual root
			// fchown/fchmod/fsync and one-way partial failure are the only claimed scope.
			roots := profileFixtureOwnedV3(t, ids.APIUID, ids.APIGID)
			scan, e := scanRoutedProfileV3(context.Background(), roots, ids.APIUID, ids.APIGID, routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768})
			if e != nil {
				t.Fatal(e)
			}
			defer scan.Close()
			swapped := false
			sentinel := errors.New("injected metadata phase interruption")
			access, e := scan.convert(context.Background(), gid, func(at string) error {
				if point == "swap-before-file" && at == "before_file:0:checkpoint.lock" {
					path := roots[0].Name()
					if e := os.Rename(path, path+"-retained"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
					swapped = true
				}
				if at == point {
					return sentinel
				}
				return nil
			})
			if point == "complete" {
				if e != nil || access[0].OwnerUID != ids.APIUID || access[0].ReaderGID != gid {
					t.Fatal(access, e)
				}
				return
			}
			if point == "swap-before-file" {
				if !swapped || e == nil || access != ([4]routedAccessRecordV3{}) {
					t.Fatal("directory swap acknowledged", e)
				}
				entries, re := os.ReadDir(roots[0].Name())
				if re != nil || len(entries) != 0 {
					t.Fatal("replacement was written", re)
				}
				return
			}
			if !errors.Is(e, sentinel) || access != ([4]routedAccessRecordV3{}) {
				t.Fatal("partial conversion acknowledged", access, e)
			}
			if next, e := scan.convert(context.Background(), gid, nil); e == nil || next != ([4]routedAccessRecordV3{}) {
				t.Fatal("partial conversion automatically repaired/adopted")
			}
		})
	}
}
