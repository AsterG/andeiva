// Package localchannel binds listener and observation operations to inherited,
// private supervisor-created channels. It does not open sockets or execute tools.
package localchannel

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/locallistener"
	"github.com/AsterG/andeiva/internal/localobserve"
)

var ErrChannel = errors.New("ANDEIVA_LOCAL_CONTROL_UNAVAILABLE")

// Binding is trusted launch metadata. A request cannot change process identity,
// choose a PID/path, enter another namespace or rebind a previous API instance.
type Binding struct {
	Run        string `json:"run"`
	Instance   string `json:"instance"`
	Generation uint64 `json:"generation"`
	Namespace  uint64 `json:"namespace"`
	UID        uint32 `json:"uid"`
}

func (b Binding) valid() bool {
	for _, s := range []string{b.Run, b.Instance} {
		d, err := hex.DecodeString(s)
		if err != nil || len(d) != 16 || hex.EncodeToString(d) != s {
			return false
		}
	}
	return b.Generation > 0 && b.Namespace > 0 && b.UID > 0
}

type message struct {
	Binding   Binding             `json:"binding"`
	Sequence  uint64              `json:"sequence"`
	Operation string              `json:"operation"`
	Revision  *configpoc.Revision `json:"revision,omitempty"`
}
type response struct {
	Binding  Binding                 `json:"binding"`
	Sequence uint64                  `json:"sequence"`
	Registry *locallistener.Registry `json:"registry,omitempty"`
	Kernel   *localobserve.Snapshot  `json:"kernel,omitempty"`
	Error    string                  `json:"error,omitempty"`
}

type Worker interface {
	Apply(context.Context, configpoc.Revision) error
	Registry() (locallistener.Registry, error)
}
type Collector interface {
	Observe() (localobserve.Snapshot, error)
}

type Client struct {
	mu             sync.Mutex
	conn           io.ReadWriteCloser
	scan           *bufio.Scanner
	binding        Binding
	sequence       uint64
	observer, dead bool
}

// The supervisor must supply a private inherited stream. This package is not an
// authentication mechanism for a public listener or caller-selected file path.
func New(conn io.ReadWriteCloser, binding Binding, observer bool) (*Client, error) {
	if conn == nil || !binding.valid() {
		return nil, ErrChannel
	}
	scan := bufio.NewScanner(conn)
	scan.Buffer(make([]byte, 4096), firewallipc.MaxFrame)
	return &Client{conn: conn, scan: scan, binding: binding, observer: observer}, nil
}
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dead = true
	return c.conn.Close()
}

func (c *Client) call(parent context.Context, operation string, revision *configpoc.Revision) (response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead || c.sequence == ^uint64(0) || parent.Err() != nil || (c.observer && operation != "kernel") || (!c.observer && operation != "apply" && operation != "registry") {
		return response{}, ErrChannel
	}
	c.sequence++
	m := message{Binding: c.binding, Sequence: c.sequence, Operation: operation, Revision: revision}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	type result struct {
		reply response
		err   error
	}
	done := make(chan result, 1)
	go func() {
		if write(c.conn, m) != nil || !c.scan.Scan() {
			done <- result{err: ErrChannel}
			return
		}
		var r response
		if firewallipc.Decode(c.scan.Bytes(), &r) != nil || r.Binding != c.binding || r.Sequence != m.Sequence || !validResponse(r, operation) {
			done <- result{err: ErrChannel}
			return
		}
		done <- result{reply: r}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			c.dead = true
			_ = c.conn.Close()
			return response{}, ErrChannel
		}
		if r.reply.Error != "" {
			return response{}, ErrChannel
		}
		return r.reply, nil
	case <-ctx.Done():
		c.dead = true
		_ = c.conn.Close()
		return response{}, ErrChannel
	}
}

func (c *Client) Apply(ctx context.Context, r configpoc.Revision) error {
	_, err := c.call(ctx, "apply", &r)
	return err
}
func (c *Client) Registry(ctx context.Context) (locallistener.Registry, error) {
	r, err := c.call(ctx, "registry", nil)
	if err != nil {
		return locallistener.Registry{}, err
	}
	return *r.Registry, nil
}
func (c *Client) Observe(ctx context.Context) (localobserve.Snapshot, error) {
	r, err := c.call(ctx, "kernel", nil)
	if err != nil {
		return localobserve.Snapshot{}, err
	}
	return *r.Kernel, nil
}

func validResponse(r response, operation string) bool {
	if r.Error != "" {
		return r.Error == ErrChannel.Error() && r.Registry == nil && r.Kernel == nil
	}
	switch operation {
	case "apply":
		return r.Registry == nil && r.Kernel == nil
	case "registry":
		return r.Registry != nil && r.Kernel == nil && len(r.Registry.Bindings) <= 8 && r.Registry.Draining >= 0 && r.Registry.Draining <= 16
	case "kernel":
		if r.Kernel == nil || r.Registry != nil {
			return false
		}
		o := r.Kernel
		return o.RunID == r.Binding.Run && o.Instance == r.Binding.Instance && o.Generation == r.Binding.Generation && o.Namespace == r.Binding.Namespace && o.StartTime > 0 && len(o.Sockets) <= 8 && len(o.Foreign) == 0
	}
	return false
}

func write(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) >= firewallipc.MaxFrame {
		return ErrChannel
	}
	data = append(data, '\n')
	n, err := out.Write(data)
	if err != nil || n != len(data) {
		return ErrChannel
	}
	return nil
}

// Serve owns one pinned channel for one role. Supplying both authorities is
// forbidden: the unprivileged worker must not become a process-identity oracle.
func Serve(ctx context.Context, conn io.ReadWriteCloser, binding Binding, worker Worker, collector Collector) error {
	if conn == nil || !binding.valid() || (worker == nil) == (collector == nil) {
		return ErrChannel
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	scan := bufio.NewScanner(conn)
	scan.Buffer(make([]byte, 4096), firewallipc.MaxFrame)
	var sequence uint64
	for scan.Scan() {
		var m message
		if firewallipc.Decode(scan.Bytes(), &m) != nil || m.Binding != binding || sequence == ^uint64(0) || m.Sequence != sequence+1 {
			return ErrChannel
		}
		sequence = m.Sequence
		r := response{Binding: binding, Sequence: sequence}
		var err error
		switch {
		case worker != nil && m.Operation == "apply" && m.Revision != nil:
			canonical, e := configpoc.Canonical(m.Revision.Config)
			if e != nil || canonical.Hash != m.Revision.Hash {
				return ErrChannel
			}
			bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
			err = worker.Apply(bounded, canonical)
			cancel()
		case worker != nil && m.Operation == "registry" && m.Revision == nil:
			var registry locallistener.Registry
			registry, err = worker.Registry()
			r.Registry = &registry
		case collector != nil && m.Operation == "kernel" && m.Revision == nil:
			var snapshot localobserve.Snapshot
			snapshot, err = collector.Observe()
			r.Kernel = &snapshot
		default:
			return ErrChannel
		}
		if err != nil {
			r.Error = ErrChannel.Error()
			r.Registry, r.Kernel = nil, nil
		}
		if !validResponse(r, m.Operation) || write(conn, r) != nil {
			return ErrChannel
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrChannel
}
