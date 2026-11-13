package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"golang.org/x/sys/unix"
)

// Receipt and Binding are inherited from root's authenticated bootstrap. They
// are not service options decoded from administrative requests.
type RoutedFreshScopeOptionsV3 struct {
	Receipt *os.File
	Binding RoutedFreshScopeBindingV3
}

type routedFreshScopeV3 struct {
	mu        sync.Mutex
	file      *os.File
	binding   RoutedFreshScopeBindingV3
	reader    *configpoc.RoutedSelectionReaderV2
	authority configpoc.RoutedAuthorityV1
	kernel    *routedKernelV3
	work      string // Correlation only; every preparation independently rereads selected work.
	reboot    bool   // Set only by the separate kernel-bound v4 constructor.
}

func validateRetirementFileV3(file *os.File) error {
	if file == nil || file.Fd() > math.MaxInt {
		return ErrIdentity
	}
	fd := int(file.Fd())
	var st unix.Stat_t
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Size != RootRetirementReceiptSizeV3 {
		return ErrIdentity
	}
	if _, err = unix.Fgetxattr(fd, "system.posix_acl_access", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return ErrIdentity
	}
	return nil
}

func readRetirementFileV3(file *os.File, binding RoutedFreshScopeBindingV3) (RootRetirementReceiptV3, error) {
	if !retirementHashV3(binding.ReceiptSHA256) || !retirementIdentityV3(binding.NewIdentity) || validateRetirementFileV3(file) != nil {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	raw := make([]byte, RootRetirementReceiptSizeV3)
	if n, err := file.ReadAt(raw, 0); err != nil || n != len(raw) || validateRetirementFileV3(file) != nil || retirementDigestV3(raw) != binding.ReceiptSHA256 {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	r, err := DecodeRootRetirementReceiptV3(raw)
	n := binding.NewIdentity
	if err != nil || r.Old.BootID != n.BootID || r.Old.Host != n.Host || r.Old.UID != n.UID || r.Old.GID != n.GID || r.Old.RunID == n.RunID || r.Old.Namespace == n.Namespace {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil || now.Nano() < r.DrainedAtBootNS {
		return RootRetirementReceiptV3{}, ErrIdentity
	}
	return r, nil
}

func newRoutedFreshScopeV3(m Metadata, o RoutedFreshScopeOptionsV3, reader *configpoc.RoutedSelectionReaderV2, authority configpoc.RoutedAuthorityV1) (*routedFreshScopeV3, error) {
	if reader == nil || authority == nil || o.Binding.NewIdentity != authority.Identity() || validateRetirementFileV3(o.Receipt) != nil {
		return nil, ErrIdentity
	}
	fd, err := unix.FcntlInt(o.Receipt.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil || fd < 0 {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), "root-retirement-receipt")
	if _, err = readRetirementFileV3(f, o.Binding); err != nil {
		_ = f.Close()
		return nil, err
	}
	k, err := newRoutedKernelV3(m)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &routedFreshScopeV3{file: f, binding: o.Binding, reader: reader, authority: authority, kernel: k}, nil
}

func (p *routedFreshScopeV3) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

// Reuse the existing strict table-list validator and fixed kernel runner. The
// additional restriction rejects every table, including a prior lease token.
func freshScopeEmptyTablesV3(raw []byte) error {
	if _, err := routedactivation.TablePresence(raw, routedactivation.LegacyTable); err != nil {
		return err
	}
	var list struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return ErrIdentity
	}
	for _, o := range list.Objects {
		if _, ok := o["table"]; ok {
			return ErrIdentity
		}
	}
	return nil
}

func freshScopeForwardingClosedV3(prepared configpoc.RoutedPreparationV1) error {
	names := []string{"all", "default"}
	links := prepared.Dependencies.Prepared.Links
	if observed := prepared.Dependencies.Observed; observed != nil {
		links = observed.Links
	}
	for _, link := range links {
		names = append(names, link.Name)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, name := range names {
			// Names come from CanonicalDependencies, never request strings.
			file, err := os.Open("/proc/sys/net/" + family + "/conf/" + name + "/forwarding") // #nosec G304 -- Canonical kernel-bound link names, fixed proc subtree.
			if err != nil {
				return ErrIdentity
			}
			b, e := io.ReadAll(io.LimitReader(file, 4))
			closeErr := file.Close()
			if e != nil || closeErr != nil || string(b) != "0\n" {
				return ErrIdentity
			}
		}
	}
	return nil
}

func (p *routedFreshScopeV3) prepare(ctx context.Context, target, saved configpoc.RoutedActivationBundleV1) (configpoc.RoutedPreparationV1, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var empty configpoc.RoutedPreparationV1
	if !p.kernel.bound() {
		return empty, ErrIdentity
	}
	raw, err := p.kernel.execute(ctx, "tables", 0, nil)
	if err != nil || freshScopeEmptyTablesV3(raw) != nil {
		return empty, ErrIdentity
	}
	prepared, err := p.authority.PrepareBoot(ctx, target, saved)
	if err != nil {
		return empty, err
	}
	prepared.Before, err = configpoc.CanonicalOwned(prepared.Before)
	if err != nil {
		return empty, err
	}
	prepared.Dependencies, err = configpoc.CanonicalDependencies(prepared.Dependencies)
	if err != nil || prepared.Before.LegacyFirewall.Presence != configpoc.Absent || prepared.Before.RoutedFirewall.Presence != configpoc.Absent || prepared.Before.LocalServices.Presence != configpoc.Absent || prepared.Before.NetworkState != configpoc.Baseline && prepared.Before.NetworkState != configpoc.NoNetwork || freshScopeForwardingClosedV3(prepared) != nil {
		return empty, ErrIdentity
	}
	receipt, current, err := p.authority.Observe(ctx)
	if err != nil || receipt.Phase != "bootstrap" || current != "" {
		return empty, ErrIdentity
	}
	raw, err = p.kernel.execute(ctx, "tables", 0, nil)
	if err != nil || freshScopeEmptyTablesV3(raw) != nil || !p.kernel.bound() || freshScopeForwardingClosedV3(prepared) != nil {
		return empty, ErrIdentity
	}
	return prepared, nil
}

func (p *routedFreshScopeV3) ProveFreshScope(ctx context.Context, work string) (configpoc.RoutedFreshScopeEvidenceV3, error) {
	var out configpoc.RoutedFreshScopeEvidenceV3
	if p == nil || p.reboot || ctx == nil {
		return out, ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	receipt, err := readRetirementFileV3(p.file, p.binding)
	if err != nil {
		return out, err
	}
	var prepared configpoc.RoutedPreparationV1
	_, err = p.reader.ObserveFreshScopeV3(ctx, work, func(source configpoc.RoutedFreshScopeSourceV3, _ configpoc.RoutedPrepareViewV2) error {
		if source.Identity() != receipt.Old {
			return ErrIdentity
		}
		var e error
		target, saved := source.PreparationBundles()
		prepared, e = p.prepare(ctx, target, saved)
		return e
	})
	if err != nil {
		return out, err
	}
	if _, err = readRetirementFileV3(p.file, p.binding); err != nil {
		return out, err
	}
	before, _ := json.Marshal(prepared.Before)
	deps, _ := json.Marshal(prepared.Dependencies)
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return out, ErrIdentity
	}
	out = configpoc.RoutedFreshScopeEvidenceV3{Version: 3, Old: receipt.Old, New: p.binding.NewIdentity, Work: work, ReceiptSHA256: p.binding.ReceiptSHA256, MetadataSHA256: receipt.MetadataSHA256, DrainedAtBootNS: receipt.DrainedAtBootNS, ObservedAtBootNS: now.Nano(), Before: retirementDigestV3(before), Dependencies: retirementDigestV3(deps)}
	if !configpoc.ValidRoutedFreshScopeEvidenceV3(out) || ctx.Err() != nil {
		return configpoc.RoutedFreshScopeEvidenceV3{}, ErrIdentity
	}
	p.work = work
	return out, nil
}

func (p *routedFreshScopeV3) prepareSelected(ctx context.Context, target configpoc.RoutedActivationBundleV1, saved string) (configpoc.RoutedPreparationV1, error) {
	var result configpoc.RoutedPreparationV1
	if p == nil || ctx == nil {
		return result, ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r, err := p.readReceipt()
	if err != nil || p.work == "" {
		return result, ErrIdentity
	}
	_, err = p.observeScope(ctx, p.work, func(source configpoc.RoutedFreshScopeSourceV3, _ configpoc.RoutedPrepareViewV2) error {
		selected, baseline := source.PreparationBundles()
		if source.Identity() != r.Old || selected.Composite.Hash != target.Composite.Hash || baseline.Composite.Hash != saved {
			return configpoc.ErrConflict
		}
		var e error
		result, e = p.prepare(ctx, selected, baseline)
		return e
	})
	if err != nil {
		return configpoc.RoutedPreparationV1{}, err
	}
	if _, err = p.readReceipt(); err != nil || ctx.Err() != nil {
		return configpoc.RoutedPreparationV1{}, ErrIdentity
	}
	return result, nil
}

func (p *routedFreshScopeV3) verifyPlan(ctx context.Context, plan configpoc.RoutedSelectedPlanV1) error {
	if p != nil && p.reboot {
		return p.verifyRebootPlan(ctx, plan)
	}
	e := plan.FreshScopeEvidenceV3()
	if e == nil {
		return nil
	}
	if p == nil || ctx == nil {
		return ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r, err := readRetirementFileV3(p.file, p.binding)
	if err != nil || !configpoc.ValidRoutedFreshScopeEvidenceV3(*e) || e.Old != r.Old || e.New != p.binding.NewIdentity || e.New != plan.Scope().Identity || e.ReceiptSHA256 != p.binding.ReceiptSHA256 || e.MetadataSHA256 != r.MetadataSHA256 || e.DrainedAtBootNS != r.DrainedAtBootNS {
		return ErrIdentity
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil || now.Nano() < e.ObservedAtBootNS {
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
