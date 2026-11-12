// Package networkexecutor qualifies static IPv4 plans in exclusively owned,
// disposable Linux namespaces. It is not an appliance management helper.
package networkexecutor

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

var (
	ErrUnsupported = errors.New("ANDEIVA_NETWORK_EXECUTOR_UNSUPPORTED")
	ErrScope       = errors.New("ANDEIVA_NETWORK_EXECUTOR_SCOPE")
	ErrObservation = errors.New("ANDEIVA_NETWORK_EXECUTOR_OBSERVATION")
	ErrUncertain   = errors.New("ANDEIVA_NETWORK_EXECUTOR_UNCERTAIN")
	ErrBusy        = errors.New("ANDEIVA_NETWORK_EXECUTOR_BUSY")
	ErrCommand     = errors.New("ANDEIVA_NETWORK_EXECUTOR_COMMAND")
)

type operation struct {
	kind, name, address, gateway string
	metric                       uint32
}
type runner func(context.Context, operation) ([]byte, error)

var linkName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// Executor owns one namespace pin. Its creator must exclusively own all writers
// in that namespace and supply a supervisor lifetime, never an HTTP context.
// A zero Executor denies operations. Close releases the pin, without restoration.
type Executor struct {
	mu             sync.Mutex
	lifetime       context.Context
	run            runner
	release        func() error
	active         *transaction
	fenced, closed bool
}
type transaction struct {
	revision   networkplan.Revision
	baseline   observation
	operations []operation
}

// Apply supports only a canonical all-static plan with DNS mode none. All links
// must initially have no IPv4 addresses and all IPv4 routing tables must be empty.
// No link flags, IPv6, DNS, forwarding or firewall settings are changed.
func (e *Executor) Apply(ctx context.Context, revision networkplan.Revision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return err
	}
	if e.active != nil {
		return ErrBusy
	}
	canonical, err := networkplan.Canonical(revision.Config)
	if err != nil || canonical.Hash != revision.Hash {
		return ErrScope
	}
	if canonical.Config.DNS.Mode != "none" {
		return ErrUnsupported
	}
	for _, i := range canonical.Config.Interfaces {
		if i.IPv4.Mode != "static" {
			return ErrUnsupported
		}
		if netip.MustParsePrefix(i.IPv4.Address).Bits() > 30 {
			return ErrUnsupported
		}
	}
	baseline, err := e.observe(ctx)
	if err != nil {
		return err
	}
	if !baseline.empty() {
		return ErrUnsupported
	}
	binding, err := networkplan.Bind(canonical, baseline.inventory())
	if err != nil {
		return ErrScope
	}
	second, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(baseline, second) {
		return ErrObservation
	}
	again, err := networkplan.Bind(canonical, second.inventory())
	if err != nil || !reflect.DeepEqual(binding.Interfaces, again.Interfaces) {
		return ErrScope
	}
	tx := &transaction{revision: canonical, baseline: baseline}
	// Record attempts before launch: a command returning an error may have effects.
	e.active = tx
	for _, i := range canonical.Config.Interfaces {
		if err = e.checkLinks(ctx, baseline); err != nil {
			return errors.Join(err, e.restore())
		}
		op := operation{kind: "address-add", name: i.Binding.Name, address: i.IPv4.Address}
		tx.operations = append(tx.operations, op)
		if _, err = e.execute(ctx, op); err != nil {
			return errors.Join(err, e.restore())
		}
	}
	for _, i := range canonical.Config.Interfaces {
		if i.ID == canonical.Config.DefaultRoute.InterfaceID {
			if err = e.checkLinks(ctx, baseline); err != nil {
				return errors.Join(err, e.restore())
			}
			op := operation{kind: "route-add", name: i.Binding.Name, gateway: i.IPv4.Gateway, metric: canonical.Config.DefaultRoute.Metric}
			tx.operations = append(tx.operations, op)
			if _, err = e.execute(ctx, op); err != nil {
				return errors.Join(err, e.restore())
			}
		}
	}
	observed, err := e.observe(ctx)
	if err != nil || !observed.matches(canonical, baseline) {
		return errors.Join(ErrObservation, e.restore())
	}
	return nil
}

// Verify performs read-only semantic verification of the currently applied plan.
// Drift or unavailable readback fences the instance; only destruction of the
// exclusively owned disposable fixture is then safe to claim as recovery.
func (e *Executor) Verify(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return err
	}
	if e.active == nil {
		return ErrScope
	}
	observed, err := e.observe(ctx)
	if err != nil || !observed.matches(e.active.revision, e.active.baseline) {
		e.fenced = true
		return errors.Join(ErrUncertain, err)
	}
	return nil
}

func (e *Executor) checkLinks(ctx context.Context, baseline observation) error {
	observed, err := e.observe(ctx)
	if err != nil {
		return err
	}
	if !sameLinks(observed, baseline) {
		return ErrObservation
	}
	return nil
}

// Restore uses the supervisor lifetime, independently of request cancellation.
// It removes only attempted exact additions. Any uncertain compensation or
// readback permanently fences this instance; no retry can reopen admission.
func (e *Executor) Restore() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.run == nil {
		return ErrScope
	}
	if e.fenced {
		return ErrUncertain
	}
	return e.restore()
}
func (e *Executor) restore() error {
	if e.active == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(e.lifetime, 15*time.Second)
	defer cancel()
	tx := e.active
	for n := len(tx.operations) - 1; n >= 0; n-- {
		// Each compensation gets a fresh identity check. Ownership excludes other
		// writers; this observation is not atomic against foreign CAP_NET_ADMIN.
		observed, err := e.observe(ctx)
		if err != nil || !sameLinks(observed, tx.baseline) {
			e.fenced = true
			return ErrUncertain
		}
		op := tx.operations[n]
		// An unsuccessful add can leave no object. Confirm absence before skipping.
		if !observed.contains(op) {
			continue
		}
		if op.kind == "address-add" {
			op.kind = "address-delete"
		} else {
			op.kind = "route-delete"
		}
		if _, err := e.execute(ctx, op); err != nil {
			e.fenced = true
			return ErrUncertain
		}
	}
	observed, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(observed, tx.baseline) {
		e.fenced = true
		return ErrUncertain
	}
	e.active = nil
	return nil
}
func (e *Executor) ready(ctx context.Context) error {
	if ctx == nil || e.closed || e.run == nil || e.lifetime == nil {
		return ErrScope
	}
	if e.fenced {
		return ErrUncertain
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.lifetime.Err()
}
func (e *Executor) execute(ctx context.Context, op operation) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	stop := context.AfterFunc(e.lifetime, cancel)
	defer stop()
	return e.run(commandCtx, op)
}
func (e *Executor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.release != nil {
		return e.release()
	}
	return nil
}

func arguments(op operation) ([]string, error) {
	if op.kind != "links" && op.kind != "addresses" && op.kind != "routes" {
		if !linkName.MatchString(op.name) || op.name == "lo" {
			return nil, ErrScope
		}
		if op.kind == "address-add" || op.kind == "address-delete" {
			p, err := netip.ParsePrefix(op.address)
			if err != nil || !p.Addr().Is4() || p.String() != op.address || p.Bits() < 1 || p.Bits() > 30 {
				return nil, ErrScope
			}
		} else {
			ip, err := netip.ParseAddr(op.gateway)
			if err != nil || !ip.Is4() || ip.String() != op.gateway || op.metric < 1 || op.metric > 65535 {
				return nil, ErrScope
			}
		}
	}
	switch op.kind {
	case "links":
		return []string{"-j", "link", "show"}, nil
	case "addresses":
		return []string{"-4", "-j", "address", "show"}, nil
	case "routes":
		return []string{"-4", "-j", "route", "show", "table", "all"}, nil
	case "address-add", "address-delete":
		verb := "add"
		if op.kind == "address-delete" {
			verb = "del"
		}
		return []string{"-4", "address", verb, op.address, "dev", op.name}, nil
	case "route-add", "route-delete":
		verb := "add"
		if op.kind == "route-delete" {
			verb = "del"
		}
		return []string{"-4", "route", verb, "default", "via", op.gateway, "dev", op.name, "proto", "static", "metric", strconv.FormatUint(uint64(op.metric), 10)}, nil
	default:
		return nil, ErrScope
	}
}
