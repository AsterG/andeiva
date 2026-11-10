package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

const maxMessage = 32768

var errProtocol = errors.New("ANDEIVA_NFT_PROTOCOL")

type message struct {
	Run      string             `json:"run"`
	Sequence uint64             `json:"sequence"`
	Verb     string             `json:"verb"`
	Revision configpoc.Revision `json:"revision"`
	Previous configpoc.Revision `json:"previous"`
	TTL      time.Duration      `json:"ttl"`
	Lease    string             `json:"lease"`
	Request  configpoc.Request  `json:"request"`
	Surface  configpoc.Surface  `json:"surface"`
}
type reply struct {
	Namespace uint64             `json:"namespace"`
	Artifact  string             `json:"artifact,omitempty"`
	Run       string             `json:"run"`
	Sequence  uint64             `json:"sequence"`
	Error     string             `json:"error,omitempty"`
	Hash      string             `json:"hash,omitempty"`
	State     nftguardian.State  `json:"authority"`
	Snapshot  configpoc.Snapshot `json:"snapshot"`
	Audit     []configpoc.Audit  `json:"audit,omitempty"`
}

func scanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), maxMessage)
	return s
}
func decode(data []byte, out any) error {
	if len(data) > maxMessage {
		return errProtocol
	}
	keys := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(keys, 0); err != nil {
		return errProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errProtocol
	}
	if d.Decode(new(any)) != io.EOF {
		return errProtocol
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errProtocol
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errProtocol
			}
			seen[s] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e := uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return errProtocol
	}
	_, err = d.Token()
	return err
}

type channel struct {
	mu                sync.Mutex
	run               string
	seq               uint64
	out               io.WriteCloser
	input             io.ReadCloser
	in                *bufio.Scanner
	dead              bool
	expectedNamespace uint64
}

func (c *channel) call(m message) (reply, error) {
	return c.callContext(context.Background(), m)
}
func (c *channel) callContext(parent context.Context, m message) (reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return reply{}, errProtocol
	}
	c.seq++
	m.Run = c.run
	m.Sequence = c.seq
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	type outcome struct {
		r   reply
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var r reply
		if err := json.NewEncoder(c.out).Encode(m); err != nil {
			done <- outcome{r, err}
			return
		}
		if !c.in.Scan() {
			done <- outcome{r, errProtocol}
			return
		}
		if err := decode(c.in.Bytes(), &r); err != nil {
			done <- outcome{r, err}
			return
		}
		if r.Run != m.Run || r.Sequence != m.Sequence {
			done <- outcome{r, errProtocol}
			return
		}
		if c.expectedNamespace != 0 && r.Namespace != c.expectedNamespace {
			done <- outcome{r, errProtocol}
			return
		}
		if r.Error != "" {
			done <- outcome{r, errors.New(r.Error)}
			return
		}
		done <- outcome{r, nil}
	}()
	select {
	case o := <-done:
		return o.r, o.err
	case <-ctx.Done():
		c.dead = true
		_ = c.out.Close()
		_ = c.input.Close()
		return reply{}, ctx.Err()
	}
}

type remoteEngine struct{ ch *channel }

func (e *remoteEngine) Name() string { return "nft-laboratory" }
func (e *remoteEngine) Validate(c configpoc.Config) error {
	r, err := configpoc.Canonical(c)
	if err != nil {
		return err
	}
	_, err = e.ch.call(message{Verb: "validate", Revision: r})
	return err
}
func (e *remoteEngine) Apply(ctx context.Context, r configpoc.Revision) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := e.ch.callContext(ctx, message{Verb: "apply", Revision: r})
	return err
}
func (e *remoteEngine) Current() string {
	r, err := e.ch.call(message{Verb: "current"})
	if err != nil {
		return ""
	}
	return r.Hash
}
