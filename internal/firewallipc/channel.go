// Package firewallipc binds typed requests to an inherited private helper channel.
package firewallipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
)

const MaxFrame = 65536

var ErrChannel = errors.New("ANDEIVA_ADMIN_HELPER_UNAVAILABLE")

type Message struct {
	Run      string             `json:"run"`
	Sequence uint64             `json:"sequence"`
	Verb     string             `json:"verb"`
	Lease    string             `json:"lease,omitempty"`
	Revision configpoc.Revision `json:"revision"`
	Previous configpoc.Revision `json:"previous"`
	Hash     string             `json:"hash,omitempty"`
	TTL      time.Duration      `json:"ttl,omitempty"`
}
type Counter struct {
	ID      string `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
type Reply struct {
	Run          string                   `json:"run"`
	Sequence     uint64                   `json:"sequence"`
	Namespace    uint64                   `json:"namespace"`
	Artifact     string                   `json:"artifact,omitempty"`
	Hash         string                   `json:"hash,omitempty"`
	State        firewalladmin.LeaseState `json:"state"`
	Counters     []Counter                `json:"counters,omitempty"`
	CounterEpoch string                   `json:"counter_epoch,omitempty"`
	Error        string                   `json:"error,omitempty"`
}
type Compiler func(configpoc.Config) (string, error)
type Client struct {
	mu                  sync.Mutex
	in                  io.ReadCloser
	out                 io.WriteCloser
	scanner             *bufio.Scanner
	run                 string
	sequence, namespace uint64
	compile             Compiler
	dead                bool
	counterGeneration   uint64
}

func New(in io.ReadCloser, out io.WriteCloser, run string, sequence, namespace uint64, compile Compiler) (*Client, error) {
	b, e := hex.DecodeString(run)
	if e != nil || len(b) != 16 || hex.EncodeToString(b) != run || namespace == 0 || compile == nil || in == nil || out == nil {
		return nil, ErrChannel
	}
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 4096), MaxFrame)
	return &Client{in: in, out: out, scanner: s, run: run, sequence: sequence, namespace: namespace, compile: compile}, nil
}
func (c *Client) closeLocked() { c.dead = true; _ = c.in.Close(); _ = c.out.Close() }
func (c *Client) Close() error { c.mu.Lock(); defer c.mu.Unlock(); c.closeLocked(); return nil }
func (c *Client) Call(parent context.Context, m Message) (Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead || c.sequence == ^uint64(0) {
		return Reply{}, ErrChannel
	}
	if parent.Err() != nil {
		return Reply{}, parent.Err()
	}
	digest := ""
	switch m.Verb {
	case "bootstrap", "apply", "arm":
		var err error
		digest, err = c.compile(m.Revision.Config)
		canonical, e := configpoc.Canonical(m.Revision.Config)
		if err != nil || e != nil || canonical.Hash != m.Revision.Hash {
			return Reply{}, ErrChannel
		}
	}
	c.sequence++
	m.Sequence = c.sequence
	m.Run = c.run
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	type result struct {
		r                 Reply
		err               error
		valid             bool
		counterGeneration uint64
	}
	minimumGeneration := c.counterGeneration
	done := make(chan result, 1)
	go func() {
		if err := json.NewEncoder(c.out).Encode(m); err != nil {
			done <- result{err: err}
			return
		}
		if !c.scanner.Scan() {
			done <- result{err: ErrChannel}
			return
		}
		var r Reply
		if Decode(c.scanner.Bytes(), &r) != nil || r.Run != m.Run || r.Sequence != m.Sequence || r.Namespace != c.namespace || (digest != "" && r.Artifact != digest) {
			done <- result{err: ErrChannel}
			return
		}
		if r.Error != "" {
			done <- result{r: r, err: ErrChannel, valid: true}
			return
		}
		generation := minimumGeneration
		if m.Verb == "observe" {
			var valid bool
			generation, valid = counterEpochGeneration(r.CounterEpoch, c.run)
			if !valid || generation < minimumGeneration {
				done <- result{err: ErrChannel}
				return
			}
		}
		done <- result{r: r, valid: true, counterGeneration: generation}
	}()
	select {
	case r := <-done:
		if !r.valid {
			c.closeLocked()
		} else if r.err == nil {
			c.counterGeneration = r.counterGeneration
		}
		return r.r, r.err
	case <-ctx.Done():
		c.closeLocked()
		return Reply{}, ErrChannel
	}
}

func counterEpochGeneration(value, run string) (uint64, bool) {
	suffix, ok := strings.CutPrefix(value, run+".")
	if !ok {
		return 0, false
	}
	generation, err := strconv.ParseUint(suffix, 10, 64)
	return generation, err == nil && strconv.FormatUint(generation, 10) == suffix
}
func (c *Client) Name() string                           { return "firewall" }
func (c *Client) Validate(config configpoc.Config) error { _, err := c.compile(config); return err }
func (c *Client) Apply(ctx context.Context, r configpoc.Revision) error {
	s, err := c.State(ctx)
	if err != nil {
		return err
	}
	verb := "apply"
	if s.Phase == "bootstrap" {
		verb = "bootstrap"
	}
	_, err = c.Call(ctx, Message{Verb: verb, Revision: r})
	return err
}

// Current is the synchronous engine contract. Observations still have a bounded
// channel timeout; an unavailable helper cannot manufacture an effective hash.
func (c *Client) Current() string {
	r, err := c.Call(context.Background(), Message{Verb: "observe"})
	if err != nil {
		return ""
	}
	return r.Hash
}
func (c *Client) Observe(ctx context.Context) (Reply, error) {
	return c.Call(ctx, Message{Verb: "observe"})
}
func (c *Client) State(ctx context.Context) (firewalladmin.LeaseState, error) {
	r, err := c.Call(ctx, Message{Verb: "state"})
	return r.State, err
}
func (c *Client) Arm(ctx context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	_, err := c.Call(ctx, Message{Verb: "arm", Lease: id, Previous: previous, Revision: target, TTL: ttl})
	return err
}
func (c *Client) Confirm(ctx context.Context, id, hash string) error {
	_, err := c.Call(ctx, Message{Verb: "confirm", Lease: id, Hash: hash})
	return err
}
func (c *Client) Recovered(ctx context.Context) error {
	_, err := c.Call(ctx, Message{Verb: "recovered"})
	return err
}

// Authority adapts the engine's legacy Current() shape to the contextual guard.
type Authority struct{ Client *Client }

func (a Authority) Arm(ctx context.Context, id string, p, t configpoc.Revision, ttl time.Duration) error {
	return a.Client.Arm(ctx, id, p, t, ttl)
}
func (a Authority) Confirm(ctx context.Context, id, hash string) error {
	return a.Client.Confirm(ctx, id, hash)
}
func (a Authority) Current(ctx context.Context) (string, error) {
	r, err := a.Client.Observe(ctx)
	return r.Hash, err
}
func (a Authority) State(ctx context.Context) (firewalladmin.LeaseState, error) {
	return a.Client.State(ctx)
}

func Decode(data []byte, out any) error {
	if len(data) > MaxFrame {
		return ErrChannel
	}
	keys := json.NewDecoder(bytes.NewReader(data))
	if unique(keys, 0) != nil {
		return ErrChannel
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrChannel
	}
	return nil
}
func unique(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrChannel
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			name = strings.ToLower(name)
			if !ok || seen[name] {
				return ErrChannel
			}
			seen[name] = true
			if unique(d, depth+1) != nil {
				return ErrChannel
			}
		}
	case '[':
		for d.More() {
			if unique(d, depth+1) != nil {
				return ErrChannel
			}
		}
	default:
		return ErrChannel
	}
	_, err = d.Token()
	return err
}
