package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// RoutedClientV3 runs only over an assembly-authenticated private channel.
// A successful handshake fences the previous helper controller; the caller must
// complete that handshake before opening its configuration writer. No fallback
// protocol, reconnect, request replay or lease renewal is performed here.
type RoutedClientV3 struct {
	mu                  sync.Mutex
	conn                io.ReadWriteCloser
	scanner             *bufio.Scanner
	run                 string
	namespace, sequence uint64
	dead                bool
	integrity           bool
	inventory           bool
	dhcp                bool
	freshScope          bool
	rebootScope         bool
	publicationAllowed  atomic.Bool
	closingAllowed      atomic.Bool
	dhcpSelected        atomic.Bool // Scheduling hint only, never an effect grant.
}

func (c *RoutedClientV3) DHCPSelectedV4() bool { return c != nil && c.dhcpSelected.Load() }

func ConnectRoutedV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64) (*RoutedClientV3, error) {
	return connectRoutedV3(parent, conn, runtimeRun, namespace, false)
}
func ConnectRoutedIntegrityV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64) (*RoutedClientV3, error) {
	return connectRoutedV3(parent, conn, runtimeRun, namespace, true)
}
func ConnectRoutedInventoryV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64) (*RoutedClientV3, error) {
	return connectRoutedFeaturesV3(parent, conn, runtimeRun, namespace, true, true)
}
func connectRoutedV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64, integrity bool) (*RoutedClientV3, error) {
	return connectRoutedFeaturesV3(parent, conn, runtimeRun, namespace, integrity, false)
}
func connectRoutedFeaturesV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64, integrity, inventory bool) (*RoutedClientV3, error) {
	return connectRoutedCapabilitiesV3(parent, conn, runtimeRun, namespace, integrity, inventory, false, false, false)
}
func connectRoutedCapabilitiesV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64, integrity, inventory, dhcp, freshScope, rebootScope bool) (*RoutedClientV3, error) {
	if parent == nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrChannel
	}
	h := NewRoutedHelloV3(runtimeRun, namespace)
	if integrity {
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3)
	}
	if inventory {
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedInventoryCapabilityV3)
	}
	if dhcp {
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedDHCPCapabilityV3)
	}
	if freshScope {
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedFreshScopeCapabilityV3)
	}
	if rebootScope {
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedRebootScopeCapabilityV4)
	}
	data, _ := json.Marshal(h)
	if _, e := DecodeRoutedHelloV3(data, false); e != nil || parent.Err() != nil {
		_ = conn.Close()
		return nil, ErrChannel
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), RoutedFrameMaxV3)
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	type outcome struct {
		hello RoutedHelloV3
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		if json.NewEncoder(conn).Encode(h) != nil || !scanner.Scan() {
			done <- outcome{err: ErrChannel}
			return
		}
		got, e := DecodeRoutedHelloV3(scanner.Bytes(), true)
		done <- outcome{got, e}
	}()
	select {
	case out := <-done:
		if out.err != nil || out.hello.RuntimeRun != runtimeRun || out.hello.Namespace != namespace || !slices.Equal(out.hello.RequiredFeatures, h.RequiredFeatures) {
			_ = conn.Close()
			return nil, ErrChannel
		}
		return &RoutedClientV3{conn: conn, scanner: scanner, run: out.hello.Run, namespace: namespace, sequence: out.hello.Epoch << 32, integrity: integrity, inventory: inventory, dhcp: dhcp, freshScope: freshScope, rebootScope: rebootScope}, nil
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ErrChannel
	}
}
func (c *RoutedClientV3) closeLocked() {
	c.dhcpSelected.Store(false)
	c.publicationAllowed.Store(false)
	c.closingAllowed.Store(false)
	c.dead = true
	_ = c.conn.Close()
}
func (c *RoutedClientV3) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	return nil
}
func (c *RoutedClientV3) Call(parent context.Context, verb string, payload any) (result RoutedResultV3, callErr error) {
	if c == nil || parent == nil {
		return RoutedResultV3{}, ErrChannel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if callErr != nil && routedEffectVerbV3(verb) {
			c.publicationAllowed.Store(false)
			c.closingAllowed.Store(false)
		}
	}()
	if (verb == "reboot_scope" && !c.rebootScope) || (verb == "fresh_scope" && !c.freshScope) || (RoutedDHCPVerbV3(verb) && !c.dhcp) || (verb == "inventory" && !c.inventory) || (verb == "inspect" && !c.integrity) || c.dead || parent.Err() != nil || c.sequence&0xffffffff == 0xffffffff {
		return RoutedResultV3{}, ErrChannel
	}
	p, e := json.Marshal(payload)
	if e != nil {
		return RoutedResultV3{}, ErrChannel
	}
	request := RoutedRequestV3{RoutedProtocolV3, c.run, c.sequence + 1, c.namespace, "routed", verb, p}
	data, e := json.Marshal(request)
	if e != nil || len(data)+1 > RoutedFrameMaxV3 {
		return RoutedResultV3{}, ErrChannel
	}
	_, command, e := DecodeRoutedRequestV3(data, c.run, c.namespace, c.sequence)
	if e != nil {
		return RoutedResultV3{}, e
	}
	if verb == "inspect" && command.Integrity.Mode == "check" {
		c.publicationAllowed.Store(false)
		c.dhcpSelected.Store(false)
	}
	c.sequence = request.Sequence
	timeout := 3 * time.Second
	if verb == "inspect" {
		timeout = configpoc.IntegrityInspectionDeadlineV1
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type outcome struct {
		reply  RoutedReplyV3
		result RoutedResultV3
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		frame := append(data, '\n')
		n, e := c.conn.Write(frame)
		if e != nil || n != len(frame) || !c.scanner.Scan() {
			done <- outcome{err: ErrChannel}
			return
		}
		reply, result, e := DecodeRoutedReplyV3(c.scanner.Bytes(), request)
		done <- outcome{reply, result, e}
	}()
	select {
	case out := <-done:
		if out.err != nil {
			c.closeLocked()
			return RoutedResultV3{}, ErrChannel
		}
		switch out.reply.Error {
		case "":
			if ctx.Err() != nil {
				c.closeLocked()
				return RoutedResultV3{}, ErrChannel
			}
			if verb == "inspect" && command.Integrity.Mode == "check" && out.result.Integrity.State == configpoc.IntegrityCompleteV1 && out.result.Integrity.Selection == command.Integrity.Selection {
				if out.result.DHCPSelected && !c.dhcp {
					c.closeLocked()
					return RoutedResultV3{}, ErrChannel
				}
				c.dhcpSelected.Store(out.result.DHCPSelected)
				c.publicationAllowed.Store(true)
			}
			if verb == "inspect" && out.result.Integrity.State == configpoc.IntegrityCompleteV1 && out.result.Integrity.Selection == command.Integrity.Selection {
				c.closingAllowed.Store(true)
			}
			return out.result, nil
		case "ANDEIVA_CONFIG_RECOVERY_REQUIRED":
			return RoutedResultV3{}, configpoc.ErrRecovery
		case "ANDEIVA_CONFIG_CONFLICT":
			return RoutedResultV3{}, configpoc.ErrConflict
		default:
			c.closeLocked()
			return RoutedResultV3{}, ErrChannel
		}
	case <-ctx.Done():
		c.closeLocked()
		return RoutedResultV3{}, ErrChannel
	}
}

// Scope is immutable handshake correlation; it conveys no filesystem or engine
// capability and must be checked against trusted supervisor metadata.
func (c *RoutedClientV3) Scope() (string, uint64) {
	if c == nil {
		return "", 0
	}
	return c.run, c.namespace
}

// IntegrityEnabled reports only the negotiated control capability, not readiness.
func (c *RoutedClientV3) IntegrityEnabled() bool { return c != nil && c.integrity }

func routedEffectVerbV3(verb string) bool {
	switch verb {
	case "arm", "apply", "confirm", "recover", "bootstrap", "resume", "dhcp_begin", "dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_retire":
		return true
	default:
		return false
	}
}

// PublicationAllowed is private controller state, never an IPC readiness flag.
func (c *RoutedClientV3) IntegrityPublicationAllowedV1() bool {
	return c != nil && c.integrity && c.publicationAllowed.Load()
}

func (c *RoutedClientV3) IntegrityClosingAllowedV1() bool {
	return c != nil && c.integrity && c.closingAllowed.Load()
}

// InventoryEnabled reports negotiated read-only capability, never readiness.
func (c *RoutedClientV3) InventoryEnabled() bool { return c != nil && c.inventory }
func (c *RoutedClientV3) Inventory(ctx context.Context) (networkinventory.Snapshot, error) {
	if !c.InventoryEnabled() {
		return networkinventory.Snapshot{}, ErrChannel
	}
	result, err := c.Call(ctx, "inventory", struct{}{})
	if err != nil {
		return networkinventory.Snapshot{}, err
	}
	return result.Inventory, nil
}
