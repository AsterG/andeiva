package previewruntime

import (
	"context"
	"encoding/json"
	"os"

	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

type RoutedRebootScopeOptionsV4 struct {
	Receipt *os.File
	Binding RoutedRebootScopeBindingV4
}

// Old drain time is interpreted only in Old.BootID. Inode numbers may repeat
// across OS boots; the new kernel scope is independently checked by the factory.
func readRebootRetirementFileV4(file *os.File, binding RoutedRebootScopeBindingV4) (RootRetirementReceiptV3, error) {
	if !retirementHashV3(binding.ReceiptSHA256) || !retirementIdentityV3(binding.NewIdentity) || validateRetirementFileV3(file) != nil {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	raw := make([]byte, RootRetirementReceiptSizeV3)
	if n, err := file.ReadAt(raw, 0); err != nil || n != len(raw) || validateRetirementFileV3(file) != nil || retirementDigestV3(raw) != binding.ReceiptSHA256 {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	r, err := DecodeRootRetirementReceiptV3(raw)
	n := binding.NewIdentity
	if err != nil || r.Old.BootID == n.BootID || r.Old.RunID == n.RunID || r.Old.UID != n.UID || r.Old.GID != n.GID {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	return r, nil
}

func newRoutedRebootScopeV4(m Metadata, o RoutedRebootScopeOptionsV4, reader *configpoc.RoutedSelectionReaderV2, authority configpoc.RoutedAuthorityV1) (*routedFreshScopeV3, error) {
	if reader == nil || authority == nil || o.Binding.NewIdentity != authority.Identity() || m.BootID != o.Binding.NewIdentity.BootID || validateRetirementFileV3(o.Receipt) != nil {
		return nil, ErrIdentity
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	actual, e := canonicalBoot(boot)
	if err != nil || e != nil || actual != o.Binding.NewIdentity.BootID {
		return nil, ErrIdentity
	}
	fd, err := unix.FcntlInt(o.Receipt.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil || fd < 0 {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), "root-reboot-retirement-receipt")
	if _, err = readRebootRetirementFileV4(f, o.Binding); err != nil {
		_ = f.Close()
		return nil, err
	}
	k, err := newRoutedKernelV3(m)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &routedFreshScopeV3{file: f, binding: RoutedFreshScopeBindingV3(o.Binding), reader: reader, authority: authority, kernel: k, reboot: true}, nil
}

func (p *routedFreshScopeV3) readReceipt() (RootRetirementReceiptV3, error) {
	if p.reboot {
		return readRebootRetirementFileV4(p.file, RoutedRebootScopeBindingV4(p.binding))
	}
	return readRetirementFileV3(p.file, p.binding)
}
func (p *routedFreshScopeV3) observeScope(ctx context.Context, work string, observe func(configpoc.RoutedFreshScopeSourceV3, configpoc.RoutedPrepareViewV2) error) (configpoc.RoutedFreshScopeSourceV3, error) {
	if p.reboot {
		return p.reader.ObserveRebootScopeV4(ctx, work, observe)
	}
	return p.reader.ObserveFreshScopeV3(ctx, work, observe)
}

func (p *routedFreshScopeV3) ProveRebootScope(ctx context.Context, work string) (configpoc.RoutedRebootScopeEvidenceV4, error) {
	var out configpoc.RoutedRebootScopeEvidenceV4
	if p == nil || !p.reboot || ctx == nil {
		return out, ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r, err := p.readReceipt()
	if err != nil {
		return out, err
	}
	var prepared configpoc.RoutedPreparationV1
	_, err = p.observeScope(ctx, work, func(source configpoc.RoutedFreshScopeSourceV3, _ configpoc.RoutedPrepareViewV2) error {
		if source.Identity() != r.Old {
			return ErrIdentity
		}
		target, saved := source.PreparationBundles()
		var e error
		prepared, e = p.prepare(ctx, target, saved)
		return e
	})
	if err != nil {
		return out, err
	}
	if _, err = p.readReceipt(); err != nil {
		return out, err
	}
	before, _ := json.Marshal(prepared.Before)
	deps, _ := json.Marshal(prepared.Dependencies)
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return out, ErrIdentity
	}
	out = configpoc.RoutedRebootScopeEvidenceV4{Version: 4, Old: r.Old, New: p.binding.NewIdentity, Work: work, ReceiptSHA256: p.binding.ReceiptSHA256, MetadataSHA256: r.MetadataSHA256, DrainedAtOldBootNS: r.DrainedAtBootNS, ObservedAtNewBootNS: now.Nano(), Before: retirementDigestV3(before), Dependencies: retirementDigestV3(deps)}
	if !configpoc.ValidRoutedRebootScopeEvidenceV4(out) || ctx.Err() != nil {
		return configpoc.RoutedRebootScopeEvidenceV4{}, ErrIdentity
	}
	p.work = work
	return out, nil
}

func (p *routedFreshScopeV3) verifyRebootPlan(ctx context.Context, plan configpoc.RoutedSelectedPlanV1) error {
	e := plan.RebootScopeEvidenceV4()
	if e == nil || p == nil || !p.reboot || ctx == nil {
		return ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r, err := p.readReceipt()
	if err != nil || !configpoc.ValidRoutedRebootScopeEvidenceV4(*e) || e.Old != r.Old || e.New != p.binding.NewIdentity || e.New != plan.Scope().Identity || e.ReceiptSHA256 != p.binding.ReceiptSHA256 || e.MetadataSHA256 != r.MetadataSHA256 || e.DrainedAtOldBootNS != r.DrainedAtBootNS {
		return ErrIdentity
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil || now.Nano() < e.ObservedAtNewBootNS {
		return ErrIdentity
	}
	receipt, _, err := p.authority.Observe(ctx)
	if err != nil {
		return err
	}
	if receipt.Phase == "bootstrap" {
		_, target := plan.Bundles()
		base := plan.Baseline()
		if base == nil {
			return ErrIdentity
		}
		prepared, err := p.prepare(ctx, target, base.Saved)
		if err != nil {
			return err
		}
		before, _ := json.Marshal(prepared.Before)
		deps, _ := json.Marshal(prepared.Dependencies)
		if retirementDigestV3(before) != e.Before || retirementDigestV3(deps) != e.Dependencies {
			return ErrIdentity
		}
	}
	return nil
}
