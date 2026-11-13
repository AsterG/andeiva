package networkexecutor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/AsterG/andeiva/internal/networkplan"
)

// LeaseForwardingV3 controls only the pinned, already owned DHCP namespace.
// Enable requires a fresh gate/policy verification before and after the write.
// It writes only the owned namespace's IPv4 forwarding switch. Linux may reset
// IPv4 host/router defaults on that transition; native qualification must check
// the resulting profile. Host forwarding, DNS and routes are outside its scope.
type LeaseForwardingV3 struct {
	mu           sync.Mutex
	target, host *os.File
	id           OwnedNamespaceIdentity
	reader       uint32
	desired      networkplan.Revision
	indices      map[string]int
	closed       bool
}

func NewLeaseForwardingInOwnedNamespaceV3(target, host *os.File, id OwnedNamespaceIdentity, reader uint32, desired networkplan.Revision) (*LeaseForwardingV3, error) {
	r, err := CanonicalLANBootstrapPlanV3(desired)
	if err != nil || !validOwnedIdentity(id) {
		return nil, ErrScope
	}
	p, _, err := pinNamespace(target)
	if err != nil {
		return nil, err
	}
	h, _, err := pinNamespace(host)
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	f := &LeaseForwardingV3{target: p, host: h, id: id, reader: reader, desired: r, indices: map[string]int{}}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, i := range r.Config.Interfaces {
		link, e := net.InterfaceByName(i.Binding.Name)
		if e != nil || link.Index <= 0 || link.HardwareAddr.String() != i.Binding.HardwareAddress {
			_ = f.Close()
			return nil, ErrScope
		}
		f.indices[i.Binding.Name] = link.Index
	}
	if f.guard() != nil || leaseForwardingClosed(LeaseOptions{Desired: r}) != nil {
		_ = f.Close()
		return nil, ErrScope
	}
	return f, nil
}

func (f *LeaseForwardingV3) guard() error {
	if f == nil || f.closed || verifyOwnedNamespaceWithReader(f.target, f.host, f.id, f.reader) != nil {
		return ErrScope
	}
	for _, i := range f.desired.Config.Interfaces {
		link, e := net.InterfaceByName(i.Binding.Name)
		if e != nil || link.Index != f.indices[i.Binding.Name] || link.HardwareAddr.String() != i.Binding.HardwareAddress {
			return ErrScope
		}
	}
	return nil
}

func leaseForwardingValueV3(path, want string) error {
	f, err := os.Open(path) // #nosec G304 -- All callers supply fixed proc paths or validated bound interface names.
	if err != nil {
		return err
	}
	b, e := io.ReadAll(io.LimitReader(f, 4))
	closeErr := f.Close()
	if e != nil || closeErr != nil || string(b) != want {
		return ErrScope
	}
	return nil
}

func (f *LeaseForwardingV3) ipv6Closed() error {
	names := []string{"all", "default"}
	for _, i := range f.desired.Config.Interfaces {
		names = append(names, i.Binding.Name)
	}
	for _, name := range names {
		if leaseForwardingValueV3("/proc/sys/net/ipv6/conf/"+name+"/forwarding", "0\n") != nil {
			return ErrScope
		}
	}
	return nil
}

func writeLeaseForwardingV3(value string) error {
	if value != "0\n" && value != "1\n" {
		return ErrScope
	}
	f, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, e := f.WriteString(value)
	c := f.Close()
	if e != nil || c != nil || n != len(value) {
		return ErrUncertain
	}
	return nil
}

func (f *LeaseForwardingV3) VerifyClosed(ctx context.Context) error {
	if f == nil || ctx == nil {
		return ErrScope
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ctx.Err() != nil || f.guard() != nil {
		return ErrScope
	}
	return leaseForwardingClosed(LeaseOptions{Desired: f.desired})
}

func (f *LeaseForwardingV3) Disable(ctx context.Context) error {
	if f == nil || ctx == nil {
		return ErrScope
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ctx.Err() != nil || f.guard() != nil {
		return ErrScope
	}
	err := writeLeaseForwardingV3("0\n")
	if leaseForwardingClosed(LeaseOptions{Desired: f.desired}) != nil {
		return errors.Join(ErrUncertain, err)
	}
	return nil
}

func (f *LeaseForwardingV3) Enable(ctx context.Context, verify func(context.Context) error) error {
	if f == nil || ctx == nil || verify == nil {
		return ErrScope
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ctx.Err() != nil || f.guard() != nil || leaseForwardingClosed(LeaseOptions{Desired: f.desired}) != nil || verify(ctx) != nil {
		return ErrScope
	}
	err := writeLeaseForwardingV3("1\n")
	if err == nil && f.guard() == nil && f.ipv6Closed() == nil && leaseForwardingValueV3("/proc/sys/net/ipv4/ip_forward", "1\n") == nil && verify(ctx) == nil && ctx.Err() == nil {
		return nil
	}
	// The gate caller must also close its token. Compensate forwarding locally.
	closeErr := writeLeaseForwardingV3("0\n")
	return errors.Join(ErrUncertain, err, closeErr, leaseForwardingClosed(LeaseOptions{Desired: f.desired}))
}

func (f *LeaseForwardingV3) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return errors.Join(f.target.Close(), f.host.Close())
}
