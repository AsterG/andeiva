package previewnet

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"syscall"
	"time"
)

func rootPeer(c *net.UnixConn) bool {
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	var credential *syscall.Ucred
	var socketErr error
	e = raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	return e == nil && socketErr == nil && credential != nil && credential.Uid == 0 && credential.Pid > 0
}

func readFrame(c *net.UnixConn, out any) error {
	s := bufio.NewScanner(c)
	s.Buffer(make([]byte, 512), 4096)
	if !s.Scan() || decode(s.Bytes(), out) != nil {
		return ErrRuntime
	}
	return nil
}

// Request is a local root-only diagnostic client. It accepts no executable,
// path, rule or namespace argument and cannot change configuration.
func Request(ctx context.Context, r ControlRequest) (ControlReply, error) {
	var out ControlReply
	if os.Geteuid() != 0 || r.Validate() != nil {
		return out, ErrRuntime
	}
	i, e := os.Lstat(ControlPath)
	if e != nil || i.Mode()&os.ModeSocket == 0 || i.Mode().Perm() != 0600 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		return out, ErrRuntime
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	d := net.Dialer{Deadline: deadline}
	connection, e := d.DialContext(ctx, "unix", ControlPath)
	if e != nil {
		return out, ErrRuntime
	}
	defer connection.Close()
	c, ok := connection.(*net.UnixConn)
	if !ok || !rootPeer(c) {
		return out, ErrRuntime
	}
	if c.SetDeadline(deadline) != nil || json.NewEncoder(c).Encode(r) != nil || readFrame(c, &out) != nil {
		return ControlReply{}, ErrRuntime
	}
	if out.Operation != r.Operation || out.At.IsZero() || out.Error != "" || !out.Healthy {
		return out, ErrRuntime
	}
	m, e := ReadMetadata()
	if e != nil || out.RunID != m.RunID {
		return out, ErrRuntime
	}
	if (r.Operation == "status") != (out.Allowed == nil) {
		return out, ErrRuntime
	}
	return out, nil
}

func handleControl(ctx context.Context, c *net.UnixConn, f fixture, m Metadata) (ControlReply, error) {
	defer c.Close()
	if !rootPeer(c) || c.SetDeadline(time.Now().Add(10*time.Second)) != nil {
		return ControlReply{}, ErrRuntime
	}
	var r ControlRequest
	if readFrame(c, &r) != nil || r.Validate() != nil {
		return ControlReply{}, ErrRuntime
	}
	out := ControlReply{Operation: r.Operation, At: time.Now().UTC(), RunID: m.RunID}
	work, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	e := checkFixture(work, f)
	if e == nil && r.Operation != "status" {
		var allowed bool
		if r.Operation == "probe" {
			allowed, e = f.Probe(work, r.Protocol, r.Port)
		} else {
			allowed, e = f.ProbeReverse(work, r.Protocol, r.Port)
		}
		if e == nil {
			out.Allowed = &allowed
		}
	}
	out.Healthy = e == nil
	if e != nil {
		out.Error = ErrRuntime.Error()
	}
	writeErr := json.NewEncoder(c).Encode(out)
	if e != nil {
		return out, e
	}
	return out, writeErr
}

func notifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] != '/' && path[0] != '@' {
		return ErrRuntime
	}
	c, e := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if e != nil {
		return e
	}
	defer c.Close()
	if e = c.SetWriteDeadline(time.Now().Add(time.Second)); e != nil {
		return e
	}
	_, e = c.Write([]byte("READY=1\nSTATUS=Isolated preview namespaces ready"))
	return e
}
