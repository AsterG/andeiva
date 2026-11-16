package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

const RoutedDHCPOwnerRoleV3 = "--andeiva-routed-dhcp-owner-v3"
const routedDHCPOwnerFrameV3 = 8192
const routedDHCPOwnerCallV3 = 2 * time.Second

// Options are root's retained launch resources, never an administrative DTO.
type RoutedDHCPOwnerOptionsV3 struct {
	Metadata      Metadata
	Desired       networkplan.Revision
	Gateway, Host *os.File
}

// Binding is authenticated by root's bootstrap, not by its public contents.
// The acquisition process and supervising role are both pinned by pidfds.
type RoutedDHCPOwnerBindingV3 struct {
	Version                            int
	RolePID                            int32
	RoleStartTicks                     uint64
	MountNamespace, HostMountNamespace uint64
	Owner                              networkexecutor.LeaseOwner
	Desired                            networkplan.Revision
}

// LeaseOwner is an in-process type without JSON tags. Keep the inherited
// bootstrap representation explicit instead of allowing case-folded names.
type routedDHCPOwnerIdentityV3 struct {
	Namespace   uint64 `json:"namespace"`
	BootID      string `json:"boot_id"`
	RunID       string `json:"run_id"`
	Incarnation string `json:"incarnation"`
	PID         uint32 `json:"pid"`
	StartTicks  uint64 `json:"start_ticks"`
}
type routedDHCPOwnerBindingWireV3 struct {
	Version            int                       `json:"version"`
	RolePID            int32                     `json:"role_pid"`
	RoleStartTicks     uint64                    `json:"role_start_ticks"`
	MountNamespace     uint64                    `json:"mount_namespace"`
	HostMountNamespace uint64                    `json:"host_mount_namespace"`
	Owner              routedDHCPOwnerIdentityV3 `json:"owner"`
	Desired            networkplan.Revision      `json:"desired"`
}

func (b RoutedDHCPOwnerBindingV3) MarshalJSON() ([]byte, error) {
	return json.Marshal(routedDHCPOwnerBindingWireV3{b.Version, b.RolePID, b.RoleStartTicks, b.MountNamespace, b.HostMountNamespace, routedDHCPOwnerIdentityV3(b.Owner), b.Desired})
}
func (b *RoutedDHCPOwnerBindingV3) UnmarshalJSON(raw []byte) error {
	var wire routedDHCPOwnerBindingWireV3
	if routedDHCPOwnerDecodeV3(raw, &wire) != nil {
		return ErrIdentity
	}
	x := RoutedDHCPOwnerBindingV3{wire.Version, wire.RolePID, wire.RoleStartTicks, wire.MountNamespace, wire.HostMountNamespace, networkexecutor.LeaseOwner(wire.Owner), wire.Desired}
	if !routedDHCPOwnerBindingValidV3(x) {
		return ErrIdentity
	}
	*b = x
	return nil
}

// These descriptors belong exclusively to one helper incarnation. Never pass
// them to the API or retain a second writer when transferring them to a child.
type RoutedDHCPOwnerFilesV3 struct{ Request, Reply, RolePIDFD, LeasePIDFD *os.File }

func (f RoutedDHCPOwnerFilesV3) Close() error {
	var result error
	for _, file := range []*os.File{f.Request, f.Reply, f.RolePIDFD, f.LeasePIDFD} {
		if file != nil {
			if err := file.Close(); err != nil && result == nil {
				result = err
			}
		}
	}
	return result
}

type routedDHCPOwnerLeaseV3 struct {
	Event          dhcpclient.Event `json:"event"`
	Epoch          uint64           `json:"epoch"`
	DeadlineBootNS int64            `json:"deadline_boot_ns"`
}
type routedDHCPOwnerRequestV3 struct {
	Version     int    `json:"version"`
	Incarnation string `json:"incarnation"`
	Sequence    uint64 `json:"sequence"`
	Operation   string `json:"operation"`
}
type routedDHCPOwnerReplyV3 struct {
	Version     int                     `json:"version"`
	Incarnation string                  `json:"incarnation"`
	Sequence    uint64                  `json:"sequence"`
	Lease       *routedDHCPOwnerLeaseV3 `json:"lease,omitempty"`
	Unavailable bool                    `json:"unavailable,omitempty"`
}

func routedDHCPOwnerDecodeV3(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > routedDHCPOwnerFrameV3 || !jsoncheck.UniqueControlFields(raw) {
		return ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return ErrIdentity
	}
	return nil
}
func routedDHCPOwnerWriteV3(file *os.File, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > routedDHCPOwnerFrameV3 {
		return ErrIdentity
	}
	raw = append(raw, '\n')
	n, err := file.Write(raw)
	if err != nil || n != len(raw) {
		return ErrUnavailable
	}
	return nil
}
func routedDHCPOwnerScannerV3(file *os.File) *bufio.Scanner {
	s := bufio.NewScanner(file)
	s.Buffer(make([]byte, 1024), routedDHCPOwnerFrameV3)
	return s
}

func routedDHCPOwnerBindingValidV3(b RoutedDHCPOwnerBindingV3) bool {
	o := b.Owner
	n, err := networkexecutor.CanonicalLANBootstrapPlanV3(b.Desired)
	boot, bootErr := canonicalBoot([]byte(o.BootID))
	return err == nil && n.Hash == b.Desired.Hash && bootErr == nil && boot == o.BootID && b.Version == 3 && b.RolePID > 1 && b.RoleStartTicks > 0 && b.MountNamespace != 0 && b.HostMountNamespace != 0 && b.MountNamespace != b.HostMountNamespace && o.PID > 1 && o.PID <= math.MaxInt32 && uint32(b.RolePID) != o.PID && o.StartTicks > 0 && o.Namespace > 0 && ValidRun(o.RunID) && ValidRun(o.Incarnation)
}

func jsonOwnerBindingV3(b RoutedDHCPOwnerBindingV3) (RoutedDHCPOwnerBindingV3, error) {
	raw, err := json.Marshal(b)
	var detached RoutedDHCPOwnerBindingV3
	if err != nil || routedDHCPOwnerDecodeV3(raw, &detached) != nil || !routedDHCPOwnerBindingValidV3(detached) {
		return detached, ErrIdentity
	}
	return detached, nil
}

func routedDHCPOwnerEventV3(e dhcpclient.Event) bool {
	p, err := netip.ParsePrefix(e.Address)
	if err != nil || len(e.DNS) > 4 {
		return false
	}
	env := []string{"pid=" + strconv.Itoa(e.PID), "interface=" + e.Interface, "reason=" + e.Reason, "protocol=dhcp", "if_configured=false", "new_ip_address=" + p.Addr().String(), "new_subnet_cidr=" + strconv.Itoa(p.Bits()), "new_routers=" + e.Gateway, "new_dhcp_server_identifier=" + e.Server, "new_domain_name_servers=" + strings.Join(e.DNS, " "), "new_dhcp_lease_time=" + strconv.FormatUint(uint64(e.Seconds), 10)}
	canonical, err := dhcpclient.HookEvent(env, e.BootNS)
	canonical.DNS = append([]string(nil), canonical.DNS...)
	e.DNS = append([]string(nil), e.DNS...)
	return err == nil && reflect.DeepEqual(canonical, e)
}

type routedDHCPOwnerFactsV3 struct {
	binding      RoutedDHCPOwnerBindingV3
	last         routedDHCPOwnerLeaseV3
	sequence     uint64
	active       bool
	revokedEpoch uint64
}

func (f *routedDHCPOwnerFactsV3) revoke() error {
	if f.active {
		if f.sequence == math.MaxUint64 {
			return ErrIdentity
		}
		f.sequence++
	}
	f.active = false
	return ErrUnavailable
}
func (f *routedDHCPOwnerFactsV3) accept(l routedDHCPOwnerLeaseV3, now int64) (RoutedDHCPOwnerFactV3, error) {
	return f.acceptBound(l, now, routedDHCPOwnerBindingValidV3(f.binding), f.binding.Owner, f.binding.Desired, int(f.binding.Owner.PID))
}

// The caller supplies an already authenticated profile binding. Acquisition
// PID can differ from the producer identity only in the explicit v4 profile.
func (f *routedDHCPOwnerFactsV3) acceptBound(l routedDHCPOwnerLeaseV3, now int64, valid bool, owner networkexecutor.LeaseOwner, desired networkplan.Revision, acquisitionPID int) (RoutedDHCPOwnerFactV3, error) {
	var empty RoutedDHCPOwnerFactV3
	l.Event.DNS = append([]string(nil), l.Event.DNS...)
	if !valid || !routedDHCPOwnerEventV3(l.Event) || now <= 0 || l.Epoch == 0 || l.Epoch <= f.revokedEpoch || l.Epoch < f.last.Epoch || l.Event.PID != acquisitionPID || l.Event.BootNS > now || l.DeadlineBootNS <= 0 || l.DeadlineBootNS > l.Event.BootNS && l.DeadlineBootNS-l.Event.BootNS > int64(l.Event.Seconds)*int64(time.Second) {
		return empty, ErrIdentity
	}
	switch l.Event.Reason {
	case "BOUND", "RENEW", "REBIND", "REBOOT":
	default:
		return empty, ErrIdentity
	}
	n := desired.Config
	n.Interfaces = append([]networkplan.Interface(nil), n.Interfaces...)
	var wan networkplan.Binding
	for i := range n.Interfaces {
		if n.Interfaces[i].Role == networkplan.WAN {
			wan = n.Interfaces[i].Binding
			n.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: l.Event.Address, Gateway: l.Event.Gateway}
		}
	}
	if l.Event.Interface != wan.Name {
		return empty, ErrIdentity
	}
	if _, err := networkplan.Canonical(n); err != nil {
		return empty, ErrIdentity
	}
	if l.Epoch == f.last.Epoch {
		if !f.active || !reflect.DeepEqual(l, f.last) {
			return empty, ErrIdentity
		}
	} else {
		if f.sequence == math.MaxUint64 || l.Event.BootNS <= f.last.Event.BootNS {
			return empty, ErrIdentity
		}
		f.sequence++
		l.Event.DNS = append([]string(nil), l.Event.DNS...)
		f.last, f.active = l, true
	}
	if l.DeadlineBootNS <= now {
		return empty, f.revoke()
	}
	return RoutedDHCPOwnerFactV3{Epoch: l.Epoch, Fact: networkexecutor.LeaseFact{Owner: owner, Sequence: f.sequence, DesiredHash: desired.Hash, WAN: wan, Address: l.Event.Address, Gateway: l.Event.Gateway, DeadlineBootNS: l.DeadlineBootNS}}, nil
}

type RoutedDHCPOwnerReaderV3 struct {
	gate        chan struct{}
	files       RoutedDHCPOwnerFilesV3
	scanner     *bufio.Scanner
	facts       routedDHCPOwnerFactsV3
	request     uint64
	dead        bool
	alive       func() bool
	now         func() (int64, error)
	closeOnce   sync.Once
	profile     int
	incarnation string
	decode      func([]byte, routedDHCPOwnerRequestV3) (*routedDHCPOwnerLeaseV3, bool, error)
	accept      func(routedDHCPOwnerLeaseV3, int64) (RoutedDHCPOwnerFactV3, error)
}

// Current performs a new request every time. Stored fields only detect replay;
// they are never a fallback when the live owner/channel cannot be verified.
func (r *RoutedDHCPOwnerReaderV3) Current(parent context.Context) (RoutedDHCPOwnerFactV3, error) {
	var empty RoutedDHCPOwnerFactV3
	if r == nil || parent == nil {
		return empty, ErrIdentity
	}
	ctx, cancel := context.WithTimeout(parent, routedDHCPOwnerCallV3)
	defer cancel()
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return empty, ErrUnavailable
	}
	if r.dead || ctx.Err() != nil || !r.alive() || r.request == math.MaxUint64 {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	deadline, _ := ctx.Deadline()
	if r.files.Request.SetWriteDeadline(deadline) != nil || r.files.Reply.SetReadDeadline(deadline) != nil {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		_ = r.files.Request.SetWriteDeadline(time.Now())
		_ = r.files.Reply.SetReadDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	r.request++
	b := r.facts.binding
	version, incarnation := 3, b.Owner.Incarnation
	if r.profile != 0 {
		version, incarnation = r.profile, r.incarnation
	}
	q := routedDHCPOwnerRequestV3{version, incarnation, r.request, "current"}
	if routedDHCPOwnerWriteV3(r.files.Request, q) != nil || !r.scanner.Scan() {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	decode := r.decode
	if decode == nil {
		decode = decodeRoutedDHCPOwnerReplyV3
	}
	lease, unavailable, err := decode(r.scanner.Bytes(), q)
	epoch, noLease := routedDHCPNoLeaseEpochV1(err)
	if err != nil && (r.profile != 4 || err != errRoutedDHCPInitialWaitingV1 && !noLease) || ctx.Err() != nil || !r.alive() {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	if err == errRoutedDHCPInitialWaitingV1 {
		return empty, err
	}
	if noLease {
		if epoch < r.facts.last.Epoch || epoch < r.facts.revokedEpoch || r.facts.revoke() != ErrUnavailable {
			r.closeLocked()
			return empty, ErrUnavailable
		}
		r.facts.revokedEpoch = epoch
		if ctx.Err() != nil || !r.alive() {
			r.closeLocked()
			return empty, ErrUnavailable
		}
		return empty, err
	}
	if unavailable {
		return empty, r.facts.revoke()
	}
	now, err := r.now()
	if err != nil {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	accept := r.accept
	if accept == nil {
		accept = r.facts.accept
	}
	out, err := accept(*lease, now)
	if err != nil && err != ErrUnavailable {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	if ctx.Err() != nil || !r.alive() {
		r.closeLocked()
		return empty, ErrUnavailable
	}
	return out, err
}

func decodeRoutedDHCPOwnerReplyV3(raw []byte, q routedDHCPOwnerRequestV3) (*routedDHCPOwnerLeaseV3, bool, error) {
	var reply routedDHCPOwnerReplyV3
	if routedDHCPOwnerDecodeV3(raw, &reply) != nil || q.Version != 3 || reply.Version != 3 || reply.Incarnation != q.Incarnation || reply.Sequence != q.Sequence || reply.Unavailable == (reply.Lease != nil) {
		return nil, false, ErrIdentity
	}
	return reply.Lease, reply.Unavailable, nil
}
func (r *RoutedDHCPOwnerReaderV3) closeLocked() {
	r.dead = true
	r.closeOnce.Do(func() { _ = r.files.Close() })
}
func (r *RoutedDHCPOwnerReaderV3) Close() error {
	if r == nil {
		return nil
	}
	// Closing descriptors first interrupts an outstanding bounded exchange.
	r.closeOnce.Do(func() { _ = r.files.Close() })
	r.gate <- struct{}{}
	r.dead = true
	<-r.gate
	return nil
}
