//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

// RoutedParentLinkV3 is a supervisor-selected physical binding. Names alone are
// insufficient: the observed index, MAC and MTU must still match before effects.
type RoutedParentLinkV3 struct {
	Index     int
	Name, MAC string
	MTU       int
}

type routedLinkObservationV3 struct {
	Index       int      `json:"ifindex"`
	Name        string   `json:"ifname"`
	MAC         string   `json:"address"`
	MTU         int      `json:"mtu"`
	Parent      int      `json:"link_index"`
	Flags       []string `json:"flags"`
	Promiscuity int      `json:"promiscuity"`
	Info        struct {
		Kind string `json:"info_kind"`
		Data struct {
			Mode string `json:"mode"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

type routedLinkOperationV3 struct {
	kind string
	slot int
}

// RoutedGatewayLinksV3 owns only its two down, unaddressed private MACVLAN
// children. It never moves a parent, configures L3, enables forwarding or adopts
// links after restart. The supervisor must retain exclusive namespace ownership.
type RoutedGatewayLinksV3 struct {
	mu                sync.Mutex
	ctx               context.Context
	parents           [2]RoutedParentLinkV3
	macs              [2]string
	created           [2]*routedLinkObservationV3
	run               func(context.Context, routedLinkOperationV3) ([]byte, error)
	closed, uncertain bool
}

func routedLinkNameV3(slot int) string {
	if slot == 0 {
		return "lan0"
	}
	return "wan0"
}

func validRoutedParentV3(p RoutedParentLinkV3) bool {
	if p.Index <= 0 || p.MTU < 576 || p.MTU > 65535 || len(p.Name) == 0 || len(p.Name) > 15 || p.Name == "lo" {
		return false
	}
	for _, r := range p.Name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	mac, err := net.ParseMAC(p.MAC)
	return err == nil && len(mac) == 6 && mac.String() == p.MAC && mac[0]&1 == 0 && p.MAC != "00:00:00:00:00:00"
}

func newRoutedGatewayLinksV3(ctx context.Context, runID string, parents [2]RoutedParentLinkV3, run func(context.Context, routedLinkOperationV3) ([]byte, error)) (*RoutedGatewayLinksV3, error) {
	if ctx == nil || ctx.Err() != nil || !validHex(runID, 16) || run == nil || !validRoutedParentV3(parents[0]) || !validRoutedParentV3(parents[1]) || parents[0].Index == parents[1].Index || parents[0].Name == parents[1].Name || parents[0].MAC == parents[1].MAC {
		return nil, ErrIdentity
	}
	l := &RoutedGatewayLinksV3{ctx: ctx, parents: parents, run: run}
	for i := range l.macs {
		sum := sha256.Sum256([]byte(fmt.Sprintf("andeiva-private-link-v1:%s:%d", runID, i)))
		l.macs[i] = fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", sum[0], sum[1], sum[2], sum[3], sum[4])
	}
	if l.macs[0] == l.macs[1] || l.macs[0] == parents[0].MAC || l.macs[0] == parents[1].MAC || l.macs[1] == parents[0].MAC || l.macs[1] == parents[1].MAC {
		return nil, ErrIdentity
	}
	return l, nil
}

// NewRoutedGatewayLinksV3 constructs a root-only launcher capability from pinned
// namespace descriptors. linkIdentity is a persistent node-local deployment key,
// separate from the per-boot RunID, so Startup bindings keep their MAC addresses.
// No request supplies a command, pathname or namespace.
func NewRoutedGatewayLinksV3(ctx context.Context, m Metadata, host, gateway *os.File, parents [2]RoutedParentLinkV3, linkIdentity string) (*RoutedGatewayLinksV3, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || m.SchemaVersion != RoutedMetadataSchemaVersion || m.ValidateRouted() != nil || !routedLinkNamespaceV3(host, m.HostNamespace) || !routedLinkNamespaceV3(gateway, m.GatewayNamespace) {
		return nil, ErrIdentity
	}
	if current, err := namespaceID("/proc/thread-self/ns/net"); err != nil || current != m.HostNamespace {
		return nil, ErrIdentity
	}
	var l *RoutedGatewayLinksV3
	runner := func(ctx context.Context, op routedLinkOperationV3) ([]byte, error) {
		if !routedLinkNamespaceV3(host, m.HostNamespace) || !routedLinkNamespaceV3(gateway, m.GatewayNamespace) {
			return nil, ErrIdentity
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if current, err := namespaceID("/proc/thread-self/ns/net"); err != nil || current != m.HostNamespace {
			return nil, ErrIdentity
		}
		program, args, err := l.arguments(op)
		if err != nil {
			return nil, err
		}
		if trustedRoutedExecutableV3(program) != nil {
			return nil, ErrIdentity
		}
		commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(commandCtx, program, args...) // #nosec G204 -- Closed launcher operations, fixed executables and validated physical bindings; no shell.
		cmd.ExtraFiles = []*os.File{gateway}
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		cmd.WaitDelay = 200 * time.Millisecond
		var out helperOutput
		cmd.Stdout = &out
		err = cmd.Run()
		return out.Bytes(), err
	}
	var err error
	l, err = newRoutedGatewayLinksV3(ctx, linkIdentity, parents, runner)
	return l, err
}

func routedLinkNamespaceV3(f *os.File, expected uint64) bool {
	if f == nil || expected == 0 {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	return err == nil && kind == unix.CLONE_NEWNET && unix.Fstat(int(f.Fd()), &st) == nil && st.Ino == expected && unix.Fstatfs(int(f.Fd()), &fs) == nil && fs.Type == unix.NSFS_MAGIC
}

func (l *RoutedGatewayLinksV3) arguments(op routedLinkOperationV3) (string, []string, error) {
	if op.slot < 0 || op.slot > 1 {
		return "", nil, ErrConfiguration
	}
	p := l.parents[op.slot]
	name := routedLinkNameV3(op.slot)
	switch op.kind {
	case "parent":
		return "/usr/bin/ip", []string{"-d", "-j", "link", "show", "dev", p.Name}, nil
	case "gateway":
		return "/usr/bin/nsenter", []string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip", "-d", "-j", "link", "show"}, nil
	case "create":
		return "/usr/bin/ip", []string{"link", "add", "link", p.Name, "name", name, "address", l.macs[op.slot], "mtu", fmt.Sprint(p.MTU), "netns", "/proc/self/fd/3", "type", "macvlan", "mode", "private"}, nil
	case "remove":
		return "/usr/bin/nsenter", []string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip", "link", "delete", "dev", name}, nil
	case "enable":
		return "/usr/bin/nsenter", []string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip", "link", "set", "dev", name, "up"}, nil
	default:
		return "", nil, ErrConfiguration
	}
}

func (l *RoutedGatewayLinksV3) observe(ctx context.Context, op routedLinkOperationV3) ([]routedLinkObservationV3, error) {
	b, err := l.run(ctx, op)
	if err != nil || len(b) == 0 || len(b) > 65536 || !jsoncheck.UniqueFields(b) {
		return nil, ErrIdentity
	}
	var links []routedLinkObservationV3
	if json.Unmarshal(b, &links) != nil || len(links) > 3 {
		return nil, ErrIdentity
	}
	return links, nil
}

func (l *RoutedGatewayLinksV3) parentsMatch(ctx context.Context) error {
	for i, p := range l.parents {
		links, err := l.observe(ctx, routedLinkOperationV3{kind: "parent", slot: i})
		if err != nil || len(links) != 1 {
			return ErrIdentity
		}
		a := links[0]
		if a.Index != p.Index || a.Name != p.Name || a.MAC != p.MAC || a.MTU != p.MTU || a.Promiscuity != 0 || !containsRoutedLinkFlagV3(a.Flags, "UP") {
			return ErrIdentity
		}
	}
	return nil
}

func containsRoutedLinkFlagV3(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func (l *RoutedGatewayLinksV3) Create(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || l.ctx.Err() != nil || l.closed || l.uncertain || l.created[0] != nil || l.created[1] != nil {
		return ErrIdentity
	}
	if l.parentsMatch(ctx) != nil {
		return ErrIdentity
	}
	initial, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
	if err != nil || len(initial) != 1 || initial[0].Name != "lo" || !containsRoutedLinkFlagV3(initial[0].Flags, "LOOPBACK") {
		return ErrIdentity
	}
	for i := range l.parents {
		if l.parentsMatch(ctx) != nil {
			l.uncertain = true
			return ErrIdentity
		}
		if _, err := l.run(ctx, routedLinkOperationV3{kind: "create", slot: i}); err != nil {
			l.uncertain = true
			return ErrIdentity
		}
		links, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
		if err != nil {
			l.uncertain = true
			return ErrIdentity
		}
		var owned *routedLinkObservationV3
		for _, v := range links {
			if v.Name == routedLinkNameV3(i) {
				copy := v
				owned = &copy
			}
		}
		if owned == nil || owned.Index <= 0 || owned.MAC != l.macs[i] || owned.Parent != l.parents[i].Index || owned.MTU != l.parents[i].MTU || owned.Info.Kind != "macvlan" || owned.Info.Data.Mode != "private" || containsRoutedLinkFlagV3(owned.Flags, "UP") {
			l.uncertain = true
			return ErrIdentity
		}
		l.created[i] = owned
	}
	if l.parentsMatch(ctx) != nil {
		l.uncertain = true
		return ErrIdentity
	}
	return nil
}

// Enable raises only the two identities created and retained by this instance.
// The namespace manager must have disabled IPv6 and forwarding before Create.
// No address, route, listener or packet policy is installed here.
func (l *RoutedGatewayLinksV3) Enable(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || l.ctx.Err() != nil || l.closed || l.uncertain || l.created[0] == nil || l.created[1] == nil || l.parentsMatch(ctx) != nil {
		return ErrIdentity
	}
	for i, owned := range l.created {
		links, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
		actual := ownedRoutedLinkV3(links, owned)
		if err != nil || len(links) != 3 || actual == nil {
			l.uncertain = true
			return ErrIdentity
		}
		if !containsRoutedLinkFlagV3(actual.Flags, "UP") {
			if _, err = l.run(ctx, routedLinkOperationV3{kind: "enable", slot: i}); err != nil {
				l.uncertain = true
				return ErrIdentity
			}
		}
		after, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
		actual = ownedRoutedLinkV3(after, owned)
		if err != nil || len(after) != 3 || actual == nil || !containsRoutedLinkFlagV3(actual.Flags, "UP") || l.parentsMatch(ctx) != nil {
			l.uncertain = true
			return ErrIdentity
		}
	}
	return nil
}

func ownedRoutedLinkV3(links []routedLinkObservationV3, owned *routedLinkObservationV3) *routedLinkObservationV3 {
	if owned == nil {
		return nil
	}
	for i := range links {
		v := &links[i]
		if v.Name == owned.Name && v.Index == owned.Index && v.MAC == owned.MAC && v.Parent == owned.Parent && v.MTU == owned.MTU && reflect.DeepEqual(v.Info, owned.Info) && v.Promiscuity == 0 {
			return v
		}
	}
	return nil
}

// Close removes only identities positively observed after this instance created
// them. Uncertain creation/readback requires supervisor namespace teardown.
func (l *RoutedGatewayLinksV3) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(l.ctx), 10*time.Second)
	defer cancel()
	var result error
	for i := 1; i >= 0; i-- {
		owned := l.created[i]
		if owned == nil {
			continue
		}
		links, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
		if err != nil {
			result = errors.Join(result, ErrIdentity)
			continue
		}
		var actual *routedLinkObservationV3
		for _, v := range links {
			if v.Name == owned.Name {
				copy := v
				actual = &copy
			}
		}
		if actual == nil {
			result = errors.Join(result, ErrIdentity)
			continue
		}
		// Flags can legitimately change after the transactional executor starts.
		if actual.Index != owned.Index || actual.MAC != owned.MAC || actual.Parent != owned.Parent || actual.MTU != owned.MTU || !reflect.DeepEqual(actual.Info, owned.Info) {
			result = errors.Join(result, ErrIdentity)
			continue
		}
		if _, err := l.run(ctx, routedLinkOperationV3{kind: "remove", slot: i}); err != nil {
			result = errors.Join(result, err)
			continue
		}
		after, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
		if err != nil {
			result = errors.Join(result, ErrIdentity)
			continue
		}
		found := false
		for _, v := range after {
			if v.Name == owned.Name {
				found = true
			}
		}
		if found {
			result = errors.Join(result, ErrIdentity)
			continue
		}
		l.created[i] = nil
	}
	if l.uncertain {
		result = errors.Join(result, ErrIdentity)
	}
	if result == nil {
		l.closed = true
	}
	return result
}
