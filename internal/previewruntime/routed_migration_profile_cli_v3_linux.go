//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const routedReaderRegistryPathV3 = "/var/lib/andeiva-preview-package/config-reader-v1"
const routedReaderGroupNameV3 = "andeiva-config-reader"
const routedMigrationProfilePathV3 = "/etc/andeiva-preview/grouped-profile.json"

type routedReaderRegistryV3 struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	GID     uint32 `json:"gid"`
}
type routedMigrationProfileResultV3 struct {
	Version        int                     `json:"version"`
	PlanSHA256     string                  `json:"plan_sha256"`
	PreparedSHA256 string                  `json:"prepared_sha256"`
	Access         [4]routedAccessRecordV3 `json:"access"`
}

func readerGroupFromV3(registry, groups []byte, ids Identities) (uint32, error) {
	var record routedReaderRegistryV3
	if len(registry) == 0 || len(registry) > 4096 || len(groups) == 0 || len(groups) > 1<<20 || ids.Validate() != nil || !jsoncheck.UniqueControlFields(registry) || firewallipc.Decode(registry, &record) != nil || record.Version != 1 || record.Name != routedReaderGroupNameV3 || record.GID == 0 || record.GID == ^uint32(0) || record.GID == ids.APIGID || record.GID == ids.IPCGID {
		return 0, ErrIdentity
	}
	found := false
	for _, line := range strings.Split(string(groups), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return 0, ErrIdentity
		}
		gid, e := strconv.ParseUint(fields[2], 10, 32)
		if e != nil || strconv.FormatUint(gid, 10) != fields[2] {
			return 0, ErrIdentity
		}
		if fields[0] == routedReaderGroupNameV3 {
			if found || uint32(gid) != record.GID || fields[3] != "" {
				return 0, ErrIdentity
			}
			found = true
		} else if uint32(gid) == record.GID {
			return 0, ErrIdentity
		}
	}
	if !found {
		return 0, ErrIdentity
	}
	return record.GID, nil
}

// ConvertRoutedMigrationProfileV3 changes only four prepared roots. Access pins
// are operational correlation, never proof of G1, policy readback or readiness.
func ConvertRoutedMigrationProfileV3(parent context.Context, c Config) (out routedMigrationProfileResultV3, result error) {
	if parent == nil || parent.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return out, ErrIdentity
	}
	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()
	ids, e := LoadIdentities(c)
	if e != nil {
		return out, e
	}
	registry, e := readOwned(routedReaderRegistryPathV3, 0, 0, 0600, 4096)
	if e != nil {
		return out, e
	}
	groups, e := readOwned("/etc/group", 0, 0, 0644, 1<<20)
	if e != nil {
		return out, e
	}
	reader, e := readerGroupFromV3(registry, groups, ids)
	if e != nil {
		return out, e
	}
	raw, e := readOwned(migrationPreparedPathV3, 0, 0, 0600, 16384)
	if e != nil {
		return out, e
	}
	var prepared routedMigrationPreparedV3
	if !jsoncheck.UniqueControlFields(raw) || firewallipc.Decode(raw, &prepared) != nil || validateMigrationPreparedV3(prepared, prepared.PlanSHA256) != nil {
		return out, ErrConfiguration
	}
	inspected, e := InspectRoutedMigrationV3(ctx, c)
	if e != nil || inspected.PlanSHA256 != prepared.PlanSHA256 {
		return out, ErrConfiguration
	}
	if _, e = os.Lstat(routedMigrationProfilePathV3); !os.IsNotExist(e) {
		return out, ErrStorage
	}
	var roots [4]*os.Root
	defer func() {
		for _, root := range roots {
			if root != nil {
				if e := root.Close(); e != nil && result == nil {
					result = e
				}
			}
		}
		if result != nil {
			out = routedMigrationProfileResultV3{}
		}
	}()
	for i, name := range []string{"state", "admission", "plan", "emergency"} {
		roots[i], e = os.OpenRoot(routedDeploymentDataV3 + "/" + name)
		if e != nil {
			return out, e
		}
	}
	scan, e := scanRoutedProfileV3(ctx, roots, ids.APIUID, ids.APIGID, prepared.WriteBudget)
	if e != nil {
		return out, e
	}
	defer func() {
		if e := scan.Close(); e != nil && result == nil {
			result = e
		}
	}()
	if e = scan.validatePoolProfilesV3(prepared.Profiles); e != nil {
		return out, e
	}
	access, e := scan.convert(ctx, reader, nil)
	if e != nil {
		return out, e
	}
	digest := sha256.Sum256(raw)
	out = routedMigrationProfileResultV3{Version: 1, PlanSHA256: prepared.PlanSHA256, PreparedSHA256: hex.EncodeToString(digest[:]), Access: access}
	actual, e := readOwned(migrationPreparedPathV3, 0, 0, 0600, 16384)
	if e != nil || !bytes.Equal(actual, raw) {
		return out, ErrIdentity
	}
	actual, e = readOwned(routedReaderRegistryPathV3, 0, 0, 0600, 4096)
	if e != nil || !bytes.Equal(actual, registry) {
		return out, ErrIdentity
	}
	actual, e = readOwned("/etc/group", 0, 0, 0644, 1<<20)
	if e != nil || !bytes.Equal(actual, groups) {
		return out, ErrIdentity
	}
	area, e := os.OpenRoot("/etc/andeiva-preview")
	if e != nil {
		return out, e
	}
	defer func() {
		if e := area.Close(); e != nil && result == nil {
			result = e
		}
	}()
	if e = writeNew(area, "grouped-profile.json", marshal(out), 0600, 0, 0); e != nil {
		return out, e
	}
	if e = syncDirectory(area.Name()); e != nil {
		return out, e
	}
	if e = scan.revalidate(ctx, reader, true); e != nil {
		return out, e
	}
	return out, nil
}

// This comparison binds the operational pool tuple only. Bank checksums, live
// reserve ownership and selected authority still require the real helper reader.
func (p *routedProfileScanV3) validatePoolProfilesV3(profiles [3]routedProfileRecordV3) error {
	for i := 1; i < 4; i++ {
		a := &p.areas[i]
		var manifest struct {
			Format   string                 `json:"format"`
			ID       string                 `json:"id"`
			Slots    int                    `json:"slots"`
			Capacity int                    `json:"capacity"`
			Role     recoveryreserve.RoleV2 `json:"role"`
			Header   int                    `json:"header"`
		}
		data := make([]byte, 4097)
		n, e := a.lock.ReadAt(data, 0)
		if (e != nil && e != io.EOF) || n == 0 || n > 4096 {
			return ErrIdentity
		}
		data = data[:n]
		hash := sha256.Sum256(data)
		expected := ""
		for _, f := range a.files {
			if f.name == "pool.json" {
				expected = f.hash
			}
		}
		if hex.EncodeToString(hash[:]) != expected || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &manifest) != nil || manifest.Format != "andeiva.recovery.reserve.v2" || manifest.Header != 4096 || manifest.ID != profiles[i-1].ID || manifest.Role != profiles[i-1].Role || manifest.Capacity != profiles[i-1].Capacity || manifest.Slots != profiles[i-1].Slots {
			return ErrIdentity
		}
		for _, f := range a.files {
			if f.name != "pool.json" && f.info.Size() != 2*int64(manifest.Header+manifest.Capacity) {
				return ErrIdentity
			}
		}

	}
	return nil
}
