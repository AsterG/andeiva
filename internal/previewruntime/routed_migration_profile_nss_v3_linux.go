//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const profileNSSLimitV3 = 1 << 20

// Enumeration is complete only for this explicitly supported local NSS profile.
// Remote providers may suppress enumeration, so a successful getent alone is insufficient.
func profileLocalNSSV3(data []byte) error {
	if len(data) == 0 || len(data) > 65536 {
		return ErrIdentity
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		pair := strings.SplitN(line, ":", 2)
		if len(pair) != 2 {
			return ErrIdentity
		}
		name := strings.TrimSpace(pair[0])
		if name != "passwd" && name != "group" {
			continue
		}
		if seen[name] {
			return ErrIdentity
		}
		seen[name] = true
		providers := strings.Fields(pair[1])
		if len(providers) == 0 {
			return ErrIdentity
		}
		for _, provider := range providers {
			if provider != "files" && provider != "systemd" {
				return ErrIdentity
			}
		}
	}
	if !seen["passwd"] || !seen["group"] {
		return ErrIdentity
	}
	return nil
}
func profilePrimaryMembershipV3(data []byte, reader uint32) error {
	if len(data) == 0 || len(data) > profileNSSLimitV3 || data[len(data)-1] != '\n' || reader == 0 {
		return ErrIdentity
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if i >= 8192 {
			return ErrIdentity
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" || seen[fields[0]] {
			return ErrIdentity
		}
		seen[fields[0]] = true
		for _, index := range []int{2, 3} {
			n, e := strconv.ParseUint(fields[index], 10, 32)
			if e != nil || strconv.FormatUint(n, 10) != fields[index] {
				return ErrIdentity
			}
		}
		gid, _ := strconv.ParseUint(fields[3], 10, 32)
		if gid == uint64(reader) {
			return ErrIdentity
		}
	}
	return nil
}

type profileNSSOutputV3 struct{ bytes.Buffer }

func (w *profileNSSOutputV3) Write(p []byte) (int, error) {
	if len(p) > profileNSSLimitV3-w.Len() {
		return 0, ErrStorage
	}
	return w.Buffer.Write(p)
}
func enumerateProfilePasswdV3(ctx context.Context) ([]byte, error) {
	info, e := os.Lstat("/usr/bin/getent")
	if e != nil || info.Mode() != 0755 {
		return nil, ErrIdentity
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
		return nil, ErrIdentity
	}
	command := exec.CommandContext(ctx, "/usr/bin/getent", "passwd")
	command.Env = []string{"LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 500 * time.Millisecond
	var output profileNSSOutputV3
	command.Stdout = &output
	command.Stderr = io.Discard
	// Linux associates Pdeathsig with the creating thread, not the entire Go process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e = command.Start(); e != nil {
		return nil, ErrUnavailable
	}
	if e = command.Wait(); e != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return output.Bytes(), nil
}
func checkProfileNSSV3(ctx context.Context, conf []byte, reader uint32, enumerate func(context.Context) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || enumerate == nil || profileLocalNSSV3(conf) != nil {
		return ErrIdentity
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, e := enumerate(bounded)
	if e != nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	return profilePrimaryMembershipV3(data, reader)
}
