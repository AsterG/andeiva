package main

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// coordinatorCommand accepts only supervisor-created identifiers and a private,
// direct child of /var/tmp. It never accepts a program, shell, or policy string.
func coordinatorCommand(ctx context.Context, runID, state string, restart, host, gateway uint64) (*exec.Cmd, error) {
	nonce, err := hex.DecodeString(runID)
	if err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != runID || restart == 0 || restart > 0xffffffff || host == 0 || gateway == 0 || host == gateway {
		return nil, errProtocol
	}
	if filepath.Clean(state) != state || filepath.Dir(state) != "/var/tmp" || !strings.HasPrefix(filepath.Base(state), "andeiva-nft-state-") || len(filepath.Base(state)) <= len("andeiva-nft-state-") {
		return nil, errProtocol
	}
	info, err := os.Lstat(state)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errProtocol
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 1000 || stat.Gid != 1000 {
		return nil, errProtocol
	}
	// #nosec G204 -- Fixed self-executable and role, no shell; all arguments are validated above. The caller drops credentials before Start.
	return exec.CommandContext(ctx, "/proc/self/exe", "--coordinator", runID, state, strconv.FormatUint(restart<<32, 10), strconv.FormatUint(gateway, 10)), nil
}
