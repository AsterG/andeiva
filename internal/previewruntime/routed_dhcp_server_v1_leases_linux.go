//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"golang.org/x/sys/unix"
)

var routedDHCPServerLeaseFilesV1 = [...]string{"kea-leases4.csv", "kea-leases4.csv.1", "kea-leases4.csv.2", "kea-leases4.csv.output", "kea-leases4.csv.completed"}

// Kea 2.6.3 lfc_messages.mes: these counters are emitted after its maintained
// reader/writer finish. LFC_TERMINATE alone explicitly does not indicate success.
var routedDHCPServerLFCStatsV1 = regexp.MustCompile(`^Leases: ([0-9]+), attempts: ([0-9]+), errors: 0\.$`)

func (b *routedDHCPServerLogV1) clean() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return false
	}
	text := string(b.data)
	for _, bad := range []string{"ERROR", "FATAL", "WARN", "LFC_FAIL_", "LFC_RUNNING", "DHCPSRV_MEMFILE_LEASE_LOAD_ROW_ERROR"} {
		if strings.Contains(text, bad) {
			return false
		}
	}
	for _, id := range []string{"LFC_READ_STATS", "LFC_WRITE_STATS"} {
		if strings.Count(text, id) != 1 {
			return false
		}
		_, value, _ := strings.Cut(text, id)
		line, _, _ := strings.Cut(value, "\n")
		fields := routedDHCPServerLFCStatsV1.FindStringSubmatch(strings.TrimSpace(line))
		if len(fields) != 3 {
			return false
		}
		for _, n := range fields[1:] {
			if _, err := strconv.ParseUint(n, 10, 64); err != nil {
				return false
			}
		}
	}
	return strings.Count(text, "LFC_TERMINATE") == 1
}

func routedDHCPServerCheckCopiesV1(ctx context.Context, o RoutedDHCPServerResourcesV1, uid, gid uint32) error {
	// At most two payload copies plus existing 1 MiB diagnostic budget; the
	// resource envelope comes from trusted Root storage assembly, not an API.
	if o.LeaseBudgetBytes <= 0 || o.LeaseBudgetBytes > (math.MaxInt64-dhcpkea.MaxArtifactBytes)/2 {
		return ErrIdentity
	}
	var hashes [len(routedDHCPServerLeaseFilesV1)][]byte
	for i, name := range routedDHCPServerLeaseFilesV1 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		source, err := routedDHCPServerOpenLeaseV1(o.Leases, name)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return ErrIdentity
		}
		hashes[i], err = routedDHCPServerCheckCopyV1(ctx, source, o.LeaseBudgetBytes, uid, gid)
		_ = source.Close()
		if err != nil {
			return err
		}
	}
	// These hashes check that the inspected originals have not changed; they are
	// not authentication, a second database, or permission to adopt other files.
	for i, name := range routedDHCPServerLeaseFilesV1 {
		file, err := routedDHCPServerOpenLeaseV1(o.Leases, name)
		if errors.Is(err, unix.ENOENT) && hashes[i] == nil {
			continue
		}
		if err != nil || hashes[i] == nil {
			if file != nil {
				_ = file.Close()
			}
			return ErrIdentity
		}
		after, err := routedDHCPServerHashV1(file, o.LeaseBudgetBytes)
		_ = file.Close()
		if err != nil || !bytes.Equal(after, hashes[i]) {
			return ErrIdentity
		}
	}
	return nil
}

func routedDHCPServerOpenLeaseV1(dir *os.File, name string) (*os.File, error) {
	if dir == nil || !routedDHCPServerLeaseNameV1(name) {
		return nil, ErrIdentity
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "kea-original-lease")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrIdentity
	}
	return file, nil
}

func routedDHCPServerHashV1(file *os.File, budget int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, budget+1))
	if err != nil || n > budget {
		return nil, ErrIdentity
	}
	return h.Sum(nil), nil
}

func routedDHCPServerCheckCopyV1(ctx context.Context, source *os.File, budget int64, uid, gid uint32) (digest []byte, result error) {
	if uid == 0 || gid == 0 || uid >= 1<<31 || gid >= 1<<31 {
		return nil, ErrIdentity
	}
	if unix.Mount("tmpfs", "/var/lib/kea", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, fmt.Sprintf("mode=0700,size=%d,nr_inodes=128", 2*budget+dhcpkea.MaxArtifactBytes)) != nil {
		return nil, ErrUnavailable
	}
	defer func() { result = errors.Join(result, unix.Unmount("/var/lib/kea", 0)) }()
	if os.Chown("/var/lib/kea", int(uid), int(gid)) != nil {
		return nil, ErrUnavailable
	}
	copy, err := os.OpenFile(dhcpkea.LeaseFile+".1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	// Hash the exact bytes copied; later checks must compare this hash, not a
	// second read taken only after validation.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(copy, h), io.LimitReader(source, budget+1))
	if err == nil && n <= budget {
		err = copy.Chown(int(uid), int(gid))
	}
	err = errors.Join(err, copy.Close())
	if err != nil || n == 0 || n > budget {
		return nil, ErrIdentity
	}
	before := h.Sum(nil)
	log := &routedDHCPServerLogV1{}
	err = routedDHCPServerExecV1(ctx, uid, gid, log)
	if log.rowFailure() {
		return nil, errRoutedDHCPServerLeaseRowV1
	}
	if err != nil || !log.clean() {
		return nil, ErrUnavailable
	}
	if err = routedDHCPOwnerDrainV3(); err != nil {
		return nil, err
	}
	after, err := routedDHCPServerHashV1(source, budget)
	if err != nil || !bytes.Equal(before, after) {
		return nil, ErrIdentity
	}
	return before, nil
}

func (b *routedDHCPServerLogV1) rowFailure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.overflow && bytes.Contains(b.data, []byte("DHCPSRV_MEMFILE_LEASE_LOAD_ROW_ERROR"))
}
