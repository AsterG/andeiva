package firewallipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
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
}

func ConnectRoutedV3(parent context.Context, conn io.ReadWriteCloser, runtimeRun string, namespace uint64) (*RoutedClientV3, error) {
	if parent == nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrChannel
	}
	h := NewRoutedHelloV3(runtimeRun, namespace)
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
		if out.err != nil || out.hello.RuntimeRun != runtimeRun || out.hello.Namespace != namespace {
			_ = conn.Close()
			return nil, ErrChannel
		}
		return &RoutedClientV3{conn: conn, scanner: scanner, run: out.hello.Run, namespace: namespace, sequence: out.hello.Epoch << 32}, nil
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ErrChannel
	}
}
func (c *RoutedClientV3) closeLocked() { c.dead = true; _ = c.conn.Close() }
func (c *RoutedClientV3) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	return nil
}
func (c *RoutedClientV3) Call(parent context.Context, verb string, payload any) (RoutedResultV3, error) {
	if c == nil || parent == nil {
		return RoutedResultV3{}, ErrChannel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead || parent.Err() != nil || c.sequence&0xffffffff == 0xffffffff {
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
	if _, _, e = DecodeRoutedRequestV3(data, c.run, c.namespace, c.sequence); e != nil {
		return RoutedResultV3{}, e
	}
	c.sequence = request.Sequence
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
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
