//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const RoutedScopeManagementFDNameV3 = "andeiva-management-v3"

type RoutedScopeRecoveryInheritedV3 struct {
	Recovery   *RoutedScopeRecoveryV3
	Management *os.File
}

func (r *RoutedScopeRecoveryInheritedV3) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.Recovery != nil {
		err = r.Recovery.Close()
		r.Recovery = nil
	}
	if r.Management != nil {
		err = errors.Join(err, r.Management.Close())
		r.Management = nil
	}
	return err
}
func scopeRecoveryInheritedNamesV3(pid, count, names string, self int) (map[string]int, error) {
	n, err := strconv.Atoi(count)
	if err != nil || n < 1 || n > len(scopeRecoveryNamesV3)+1 || strconv.Itoa(n) != count || pid != strconv.Itoa(self) || self <= 1 {
		return nil, ErrIdentity
	}
	split := strings.Split(names, ":")
	if len(split) != n {
		return nil, ErrIdentity
	}
	allowed := map[string]bool{RoutedScopeManagementFDNameV3: true}
	for _, name := range scopeRecoveryNamesV3 {
		allowed[name] = true
	}
	found := map[string]int{}
	for i, name := range split {
		if !allowed[name] {
			return nil, ErrIdentity
		}
		if _, ok := found[name]; ok {
			return nil, ErrIdentity
		}
		found[name] = i + 3
	}
	if _, ok := found[RoutedScopeManagementFDNameV3]; !ok || (n != 1 && n != len(scopeRecoveryNamesV3)+1) {
		return nil, ErrIdentity
	}
	return found, nil
}

// TakeRoutedScopeRecoveryInheritedV3 runs in Root MAIN before opening other FDs.
// It adopts the complete named set, never assumes fdstore ordering, and rejects
// partial/unknown authority without removing anything from the manager's store.
func TakeRoutedScopeRecoveryInheritedV3(ctx context.Context) (out *RoutedScopeRecoveryInheritedV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getppid() != 1 {
		return nil, ErrIdentity
	}
	names, err := scopeRecoveryInheritedNamesV3(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES"), os.Getpid())
	if err != nil {
		return nil, err
	}
	adopted := map[string]*os.File{}
	originals := []*os.File{}
	defer func() {
		for _, f := range adopted {
			_ = f.Close()
		}
		if result == nil {
			for _, f := range originals {
				_ = f.Close()
			}
		}
	}()
	seen := map[[2]uint64]bool{}
	for name, fd := range names {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || seen[[2]uint64{uint64(st.Dev), st.Ino}] {
			return nil, ErrIdentity
		}
		seen[[2]uint64{uint64(st.Dev), st.Ino}] = true
		unix.CloseOnExec(fd)
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil || duplicate < 0 {
			return nil, ErrIdentity
		}
		adopted[name] = os.NewFile(uintptr(duplicate), "root-inherited-scope")
		originals = append(originals, os.NewFile(uintptr(fd), "systemd-inherited-scope"))
	}
	management := adopted[RoutedScopeManagementFDNameV3]
	kind, err := unix.GetsockoptInt(int(management.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	accepting, other := unix.GetsockoptInt(int(management.Fd()), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || other != nil || kind != unix.SOCK_STREAM || accepting != 1 {
		return nil, ErrIdentity
	}
	r := &RoutedScopeRecoveryInheritedV3{}
	if len(names) > 1 {
		a := RoutedScopeRecoveryAnchorsV3{adopted[scopeRecoveryNamesV3[0]], adopted[scopeRecoveryNamesV3[1]], adopted[scopeRecoveryNamesV3[2]], adopted[scopeRecoveryNamesV3[3]], adopted[scopeRecoveryNamesV3[4]], adopted[scopeRecoveryNamesV3[5]], adopted[scopeRecoveryNamesV3[6]]}
		r.Recovery, err = OpenRoutedScopeRecoveryV3(ctx, a)
		if err != nil {
			return nil, err
		}
	}
	r.Management = management
	delete(adopted, RoutedScopeManagementFDNameV3)
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	return r, nil
}
