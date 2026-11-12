package nftfixture

import (
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"

	"github.com/AsterG/andeiva/internal/firewallnft"
)

// SealAdminDeny installs the compiler's empty deny policy before the independent
// preview helper can start. It is confined to the retained gateway namespace.
func (f *Fixture) SealAdminDeny(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := firewallnft.Compile(firewallnft.DefaultConfig())
	if err != nil {
		return err
	}
	if _, err = f.run(ctx, "gateway", nftPath, []string{"-j", "-f", "-"}, "", string(a.Create)); err != nil {
		return err
	}
	return nil
}

const previewGatewayPath = "/run/andeiva-preview/netns/gateway"

// CheckPreviewListeners checks the fixed positive controls in both endpoint
// namespaces without crossing or changing the managed gateway policy.
func (f *Fixture) CheckPreviewListeners(ctx context.Context) error {
	if err := f.CheckListeners(ctx); err != nil {
		return err
	}
	return checkListenerControls(ctx, "ANDEIVA_NFT_FIXTURE_REVERSE_LISTENER", f.ProbeReverseLocal)
}

// PinPreviewGateway retains only this fixture's gateway at the fixed systemd
// namespace path. The caller must remove the pin before closing the fixture.
func (f *Fixture) PinPreviewGateway() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ns, err := f.checked("gateway")
	if err != nil {
		return err
	}
	for _, dir := range []string{"/run/andeiva-preview", "/run/andeiva-preview/netns"} {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return errors.New("ANDEIVA_PREVIEW_NAMESPACE_PATH")
		}
	}
	fd, err := syscall.Open(previewGatewayPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if err = syscall.Close(fd); err != nil {
		return err
	}
	return syscall.Mount("/proc/self/fd/"+strconv.FormatUint(uint64(ns.handle.Fd()), 10), previewGatewayPath, "", syscall.MS_BIND, "")
}
