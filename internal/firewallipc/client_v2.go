package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
)

type HelloV2 struct {
	ProtocolVersion  int      `json:"protocol_version"`
	RuntimeRun       string   `json:"runtime_run"`
	Namespace        uint64   `json:"namespace"`
	Domain           string   `json:"domain"`
	RequiredFeatures []string `json:"required_features"`
	Run              string   `json:"run,omitempty"`
	Epoch            uint64   `json:"epoch,omitempty"`
}

func NewHelloV2(runtimeRun string, namespace uint64, domain string) HelloV2 {
	return HelloV2{ProtocolVersion: 2, RuntimeRun: runtimeRun, Namespace: namespace, Domain: domain, RequiredFeatures: []string{"attach_observed.v1", "recover_scoped.v1"}}
}
func DecodeHelloV2(data []byte, reply bool) (HelloV2, error) {
	var h HelloV2
	keys := []string{"protocol_version", "runtime_run", "namespace", "domain", "required_features"}
	if reply {
		keys = append(keys, "run", "epoch")
	}
	if len(data) > MaxFrame || exactV2(data, &h, keys) != nil || h.ProtocolVersion != 2 || !runV2(h.RuntimeRun) || h.Namespace == 0 || !DomainV2(h.Domain) || len(h.RequiredFeatures) != 2 || h.RequiredFeatures[0] != "attach_observed.v1" || h.RequiredFeatures[1] != "recover_scoped.v1" || (reply && (!runV2(h.Run) || h.Epoch == 0 || h.Epoch > 0xffffffff)) {
		return h, ErrChannel
	}
	return h, nil
}

// ConnectV2 negotiates only on a channel whose kernel peer/provenance has already
// been authenticated by its assembly. It does not authenticate a supplied stream.
// Production assembly remains explicitly separate from this prepared transport.
func ConnectV2(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64, domain string, compile Compiler) (*ClientV2, error) {
	if parent == nil || conn == nil || compile == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrChannel
	}
	if parent.Err() != nil {
		_ = conn.Close()
		return nil, ErrChannel
	}
	h := NewHelloV2(runtimeRun, namespace, domain)
	data, _ := json.Marshal(h)
	if _, e := DecodeHelloV2(data, false); e != nil {
		_ = conn.Close()
		return nil, e
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	s := bufio.NewScanner(conn)
	s.Buffer(make([]byte, 4096), LocalReplyMaxFrame)
	type outcome struct {
		h   HelloV2
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		if json.NewEncoder(conn).Encode(h) != nil || !s.Scan() {
			done <- outcome{err: ErrChannel}
			return
		}
		got, e := DecodeHelloV2(s.Bytes(), true)
		done <- outcome{got, e}
	}()
	select {
	case got := <-done:
		if got.err != nil || got.h.RuntimeRun != runtimeRun || got.h.Namespace != namespace || got.h.Domain != domain {
			_ = conn.Close()
			return nil, ErrChannel
		}
		return &ClientV2{conn: conn, scanner: s, run: got.h.Run, sequence: got.h.Epoch << 32, namespace: namespace, domain: domain, compile: compile}, nil
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ErrChannel
	}
}

type ClientV2 struct {
	mu                                     sync.Mutex
	conn                                   io.ReadWriteCloser
	scanner                                *bufio.Scanner
	run, domain                            string
	sequence, namespace, counterGeneration uint64
	compile                                Compiler
	dead                                   bool
}

func (c *ClientV2) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return nil
	}
	c.dead = true
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
func (c *ClientV2) call(parent context.Context, verb string, payload any) (ResultV2, error) {
	if c == nil || parent == nil {
		return ResultV2{}, ErrChannel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead || c.conn == nil || c.scanner == nil || c.compile == nil || !DomainV2(c.domain) || c.sequence&0xffffffff == 0xffffffff {
		return ResultV2{}, ErrChannel
	}
	if parent.Err() != nil {
		return ResultV2{}, parent.Err()
	}
	p, e := json.Marshal(payload)
	if e != nil {
		return ResultV2{}, ErrChannel
	}
	m := RequestV2{ProtocolVersion: 2, Run: c.run, Sequence: c.sequence + 1, Namespace: c.namespace, Domain: c.domain, Verb: verb, Payload: p}
	data, e := json.Marshal(m)
	if e != nil {
		return ResultV2{}, ErrChannel
	}
	_, command, e := DecodeRequestV2(data)
	if e != nil {
		return ResultV2{}, e
	}
	digest := ""
	if verb == "apply" || verb == "bootstrap" || verb == "arm" {
		revision := command.Revision
		if verb == "arm" {
			revision = command.Arm.Target
		}
		digest, e = c.compile(revision.Config)
		if e != nil || !hashV2(digest) {
			return ResultV2{}, ErrChannel
		}
	}
	c.sequence = m.Sequence
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	type outcome struct {
		r   ResultV2
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		if json.NewEncoder(c.conn).Encode(m) != nil || !c.scanner.Scan() {
			done <- outcome{err: ErrChannel}
			return
		}
		r, e := DecodeReplyV2(c.scanner.Bytes(), m)
		done <- outcome{r, e}
	}()
	select {
	case got := <-done:
		if got.err == nil && digest != "" && got.r.Artifact != digest {
			got.err = ErrChannel
		}
		if got.err == nil && verb == "observe" && c.domain == "firewall" {
			generation, ok := counterEpochGeneration(got.r.CounterEpoch, c.run)
			if !ok || generation < c.counterGeneration {
				got.err = ErrChannel
			} else {
				c.counterGeneration = generation
			}
		}
		if got.err != nil {
			c.dead = true
			_ = c.conn.Close()
			return ResultV2{}, got.err
		}
		return got.r, got.err
	case <-ctx.Done():
		c.dead = true
		_ = c.conn.Close()
		return ResultV2{}, ErrChannel
	}
}
func (c *ClientV2) Name() string {
	if c == nil || !DomainV2(c.domain) {
		return ""
	}
	if c.domain == "local_services" {
		return "local-services"
	}
	return "firewall"
}
func (c *ClientV2) Validate(cfg configpoc.Config) error {
	if c == nil || c.compile == nil {
		return ErrChannel
	}
	_, e := c.compile(cfg)
	return e
}
func (c *ClientV2) Snapshot(ctx context.Context) (ObservedScope, error) {
	r, e := c.call(ctx, "state", struct{}{})
	return ObservedScope{r.State, r.Hash}, e
}
func (c *ClientV2) State(ctx context.Context) (firewalladmin.LeaseState, error) {
	o, e := c.Snapshot(ctx)
	return o.State, e
}
func (c *ClientV2) AttachObserved(ctx context.Context, o ObservedScope) error {
	_, e := c.call(ctx, "attach_observed", o)
	return e
}
func (c *ClientV2) Observe(ctx context.Context) (ResultV2, error) {
	return c.call(ctx, "observe", struct{}{})
}
func (c *ClientV2) Current() string {
	o, e := c.Snapshot(context.Background())
	if e != nil {
		return ""
	}
	return o.Hash
}
func (c *ClientV2) Bootstrap(ctx context.Context, r configpoc.Revision) error {
	_, e := c.call(ctx, "bootstrap", RevisionPayloadV2{r})
	return e
}
func (c *ClientV2) Apply(ctx context.Context, r configpoc.Revision) error {
	_, e := c.call(ctx, "apply", RevisionPayloadV2{r})
	return e
}
func (c *ClientV2) Arm(ctx context.Context, id string, p, t configpoc.Revision, ttl time.Duration) error {
	_, e := c.call(ctx, "arm", ArmPayloadV2{id, p, t, ttl})
	return e
}
func (c *ClientV2) Confirm(ctx context.Context, id, hash string) error {
	_, e := c.call(ctx, "confirm", ConfirmPayloadV2{id, hash})
	return e
}
func (c *ClientV2) RecoverScoped(ctx context.Context, s firewalladmin.LeaseState) error {
	_, e := c.call(ctx, "recover_scoped", RecoveryScope{s.ID, s.Previous, s.Target, s.Deadline})
	return e
}

type AuthorityV2 struct{ Client *ClientV2 }

func (c *ClientV2) ArmUntil(ctx context.Context, id string, p, t configpoc.Revision, deadline time.Time) error {
	_, e := c.call(ctx, "arm_until", ArmUntilPayloadV2{id, p, t, deadline})
	return e
}
func (c *ClientV2) ApplyLease(ctx context.Context, r configpoc.Revision, s firewalladmin.LeaseState) error {
	_, e := c.call(ctx, "apply_scoped", ApplyScopedPayloadV2{r, RecoveryScope{s.ID, s.Previous, s.Target, s.Deadline}})
	return e
}
func (c *ClientV2) ConfirmLease(ctx context.Context, s firewalladmin.LeaseState) error {
	_, e := c.call(ctx, "confirm_scoped", RecoveryScope{s.ID, s.Previous, s.Target, s.Deadline})
	return e
}
func (a AuthorityV2) ArmUntil(ctx context.Context, id string, p, t configpoc.Revision, deadline time.Time) error {
	return a.Client.ArmUntil(ctx, id, p, t, deadline)
}
func (a AuthorityV2) ApplyLease(ctx context.Context, r configpoc.Revision, s firewalladmin.LeaseState) error {
	return a.Client.ApplyLease(ctx, r, s)
}
func (a AuthorityV2) ConfirmLease(ctx context.Context, s firewalladmin.LeaseState) error {
	return a.Client.ConfirmLease(ctx, s)
}
func (a AuthorityV2) RecoverScoped(ctx context.Context, s firewalladmin.LeaseState) error {
	return a.Client.RecoverScoped(ctx, s)
}

func (a AuthorityV2) Arm(ctx context.Context, id string, p, t configpoc.Revision, ttl time.Duration) error {
	return a.Client.Arm(ctx, id, p, t, ttl)
}
func (a AuthorityV2) Confirm(ctx context.Context, id, hash string) error {
	return a.Client.Confirm(ctx, id, hash)
}
func (a AuthorityV2) State(ctx context.Context) (firewalladmin.LeaseState, error) {
	return a.Client.State(ctx)
}
func (a AuthorityV2) Current(ctx context.Context) (string, error) {
	o, e := a.Client.Snapshot(ctx)
	return o.Hash, e
}
