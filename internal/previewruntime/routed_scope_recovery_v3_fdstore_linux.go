//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

var scopeRecoveryNamesV3 = [6]string{"andeiva-scope-record-v3", "andeiva-scope-gateway-v3", "andeiva-scope-mount-v3", "andeiva-scope-underlay-v3", "andeiva-scope-directory-v3", "andeiva-scope-cgroup-v3"}

type scopeRecoveryStoredV3 struct {
	Mode, Major, Minor    uint32
	Inode                 uint64
	Rmajor, Rminor, Flags uint32
}

// systemd257 DumpUnitFileDescriptorStore exposes fstat/F_GETFL facts. Names are
// not unique and order is unspecified, so neither alone identifies an anchor.
func scopeRecoveryStoreMatchesV3(raw []byte, want map[string]scopeRecoveryStoredV3) bool {
	if len(raw) == 0 || len(raw) > 32768 || len(want) != len(scopeRecoveryNamesV3) || !jsoncheck.UniqueControlFields(raw) {
		return false
	}
	var envelope struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || envelope.Type != "a(suuutuusu)" || len(envelope.Data) != 1 {
		return false
	}
	var entries [][]json.RawMessage
	if json.Unmarshal(envelope.Data[0], &entries) != nil || len(entries) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if len(entry) != 9 {
			return false
		}
		var name, path string
		var got scopeRecoveryStoredV3
		fields := []any{&name, &got.Mode, &got.Major, &got.Minor, &got.Inode, &got.Rmajor, &got.Rminor, &path, &got.Flags}
		for i, field := range fields {
			if json.Unmarshal(entry[i], field) != nil {
				return false
			}
		}
		expected, ok := want[name]
		if !ok || seen[name] || got != expected || len(path) > 4096 {
			return false
		}
		seen[name] = true
	}
	return true
}

// VerifyStored checks actual manager readback; a successful notify barrier alone
// would not prove acceptance. It does not prove process drainage or retirement.
func (r *RoutedScopeRecoveryV3) VerifyStored(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revalidateLocked(ctx) != nil {
		return ErrIdentity
	}
	want := make(map[string]scopeRecoveryStoredV3, len(r.files))
	for i, f := range r.files {
		_, st, err := scopeRecoveryIdentityV3(f)
		if err != nil {
			return ErrIdentity
		}
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil || flags < 0 || uint64(flags) > uint64(^uint32(0)) {
			return ErrIdentity
		}
		// systemd masks raw O_LARGEFILE for architecture-independent dump output.
		want[scopeRecoveryNamesV3[i]] = scopeRecoveryStoredV3{Mode: st.Mode, Major: unix.Major(uint64(st.Dev)), Minor: unix.Minor(uint64(st.Dev)), Inode: st.Ino, Rmajor: unix.Major(uint64(st.Rdev)), Rminor: unix.Minor(uint64(st.Rdev)), Flags: uint32(flags) &^ 0x8000}
	}
	if trustedRoutedExecutableV3("/usr/bin/busctl") != nil {
		return ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/busctl", "--system", "--json=short", "--timeout=2s", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "DumpUnitFileDescriptorStore", "s", "andeiva-preview-grouped.service")
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	err := cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil || !scopeRecoveryStoreMatchesV3(output.Bytes(), want) || r.revalidateLocked(ctx) != nil {
		return ErrIdentity
	}
	return nil
}

type scopeRecoveryOutputV3 struct{ bytes.Buffer }

func (b *scopeRecoveryOutputV3) Write(p []byte) (int, error) {
	if len(p) > 32768-b.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}
