//go:build linux

package previewruntime

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
)

const migrationProcLimitV3 = 64 << 10

func readRoutedMigrationProcV3(name string) ([]byte, error) {
	var file *os.File
	var err error
	switch name {
	case "tcp":
		file, err = os.Open("/proc/net/tcp")
	case "tcp6":
		file, err = os.Open("/proc/net/tcp6")
	case "udp":
		file, err = os.Open("/proc/net/udp")
	case "udp6":
		file, err = os.Open("/proc/net/udp6")
	default:
		return nil, ErrIdentity
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(file, migrationProcLimitV3+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > migrationProcLimitV3 {
		return nil, ErrUnavailable
	}
	return data, nil
}

func inspectRoutedMigrationInetV3(ctx context.Context, read func(string) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return ErrUnavailable
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := read(name)
		if err != nil || migrationInetEmptyV3(name, data) != nil || ctx.Err() != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// This is a conservative deployment profile, not socket-owner attribution.
// Refuse a busy namespace; never delete its sockets or call them ANDEIVA-owned.
func migrationInetEmptyV3(name string, data []byte) error {
	udp := name == "udp" || name == "udp6"
	ipv6 := name == "tcp6" || name == "udp6"
	if (!udp && name != "tcp" && name != "tcp6") || len(data) == 0 || len(data) > migrationProcLimitV3 || data[len(data)-1] != '\n' {
		return ErrUnavailable
	}
	lines := strings.Split(string(data), "\n")
	remote := "rem_address"
	addressSize := 8
	if ipv6 {
		remote = "remote_address"
		addressSize = 32
	}
	header := []string{"sl", "local_address", remote, "st", "tx_queue", "rx_queue", "tr", "tm->when", "retrnsmt", "uid", "timeout", "inode"}
	if udp {
		header = append(header, "ref", "pointer", "drops")
	}
	got := strings.Fields(lines[0])
	if strings.Join(got, " ") != strings.Join(header, " ") {
		return ErrUnavailable
	}
	for _, line := range lines[1 : len(lines)-1] {
		columns := strings.Fields(line)
		if len(columns) < 10 || len(columns) > 24 {
			return ErrUnavailable
		}
		slot, ok := strings.CutSuffix(columns[0], ":")
		if !ok || !migrationProcDecimalV3(slot, 32) || !migrationProcAddressV3(columns[1], addressSize) || !migrationProcAddressV3(columns[2], addressSize) || !migrationProcHexV3(columns[3], 2) || !migrationProcPairV3(columns[4], 8, 8) || !migrationProcPairV3(columns[5], 2, 8) || !migrationProcHexV3(columns[6], 8) || !migrationProcDecimalV3(columns[7], 32) || !migrationProcDecimalV3(columns[8], 64) || !migrationProcDecimalV3(columns[9], 64) {
			return ErrUnavailable
		}
		state, err := strconv.ParseUint(columns[3], 16, 8)
		if err != nil || state < 1 || state > 12 || udp || state == 10 {
			return ErrUnavailable
		}
	}
	return nil
}
func migrationProcHexV3(value string, size int) bool {
	if len(value) != size {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func migrationProcPairV3(value string, leftSize, rightSize int) bool {
	left, right, ok := strings.Cut(value, ":")
	return ok && migrationProcHexV3(left, leftSize) && migrationProcHexV3(right, rightSize)
}
func migrationProcAddressV3(value string, size int) bool { return migrationProcPairV3(value, size, 4) }
func migrationProcDecimalV3(value string, bits int) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, bits)
	return err == nil
}
