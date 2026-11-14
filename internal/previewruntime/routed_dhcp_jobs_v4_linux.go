//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

const routedDHCPJobFrameV4 = 16384

type routedDHCPJobV4 struct {
	Version   int                             `json:"version"`
	Run       string                          `json:"run"`
	Namespace uint64                          `json:"namespace"`
	Sequence  uint64                          `json:"sequence"`
	Operation string                          `json:"operation"`
	Work      configpoc.RoutedWorkReferenceV1 `json:"work"`
}
type routedDHCPJobReplyV4 struct {
	Job         routedDHCPJobV4              `json:"job"`
	Unavailable bool                         `json:"unavailable"`
	Binding     *RoutedDHCPDeferredBindingV4 `json:"binding,omitempty"`
}
type routedDHCPJobPeerV4 struct {
	pid      int
	uid, gid uint32
}

func routedDHCPJobValidV4(q routedDHCPJobV4, m Metadata, last uint64) bool {
	return q.Version == 4 && q.Run == m.RunID && q.Namespace == m.GatewayNamespace && last != math.MaxUint64 && q.Sequence == last+1 && (q.Operation == "prepare" || q.Operation == "activate" || q.Operation == "stop") && routedPrivateHashV4(q.Work.Work) && q.Work.Lineage != "" && len(q.Work.Lineage) <= 128 && q.Work.Generation > 0
}

func routedDHCPJobSocketV4(f *os.File) (*net.UnixConn, error) {
	if f == nil {
		return nil, ErrIdentity
	}
	var st unix.Stat_t
	fd := f.Fd()
	kind, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_SEQPACKET || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil {
		return nil, ErrIdentity
	}
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, ErrIdentity
	}
	return u, nil
}

func routedDHCPJobPairV4() (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	a, b := os.NewFile(uintptr(fds[0]), "routed-root-jobs"), os.NewFile(uintptr(fds[1]), "routed-helper-jobs")
	// Enable credentials before either peer can enqueue its first datagram.
	if unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil {
		_ = a.Close()
		_ = b.Close()
		return nil, nil, ErrIdentity
	}
	c, err := routedDHCPJobSocketV4(a)
	_ = a.Close()
	if err != nil {
		_ = b.Close()
		return nil, nil, err
	}
	return c, b, nil
}

func routedDHCPJobSendV4(c *net.UnixConn, value any, files []*os.File) error {
	if c == nil || len(files) > 3 {
		return ErrIdentity
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > routedDHCPJobFrameV4 {
		return ErrIdentity
	}
	var rights []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			if f == nil || f.Fd() > math.MaxInt32 {
				return ErrIdentity
			}
			fds[i] = int(f.Fd())
		}
		rights = unix.UnixRights(fds...)
	}
	n, oob, err := c.WriteMsgUnix(raw, rights, nil)
	if err != nil || n != len(raw) || oob != len(rights) {
		return ErrUnavailable
	}
	return nil
}

func routedDHCPJobReceiveV4(c *net.UnixConn, peer routedDHCPJobPeerV4, out any) (files []*os.File, result error) {
	if c == nil || peer.pid <= 1 {
		return nil, ErrIdentity
	}
	raw := make([]byte, routedDHCPJobFrameV4+1)
	oob := make([]byte, unix.CmsgSpace(4*4)+unix.CmsgSpace(unix.SizeofUcred))
	n, on, flags, _, err := c.ReadMsgUnix(raw, oob)
	defer func() {
		if result != nil {
			for _, f := range files {
				_ = f.Close()
			}
			files = nil
		}
	}()
	controls, parseErr := unix.ParseSocketControlMessage(oob[:on])
	credentials := false
	for _, message := range controls {
		switch {
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS:
			fds, e := unix.ParseUnixRights(&message)
			if e != nil {
				parseErr = e
				continue
			}
			for _, fd := range fds {
				unix.CloseOnExec(fd)
				files = append(files, os.NewFile(uintptr(fd), "routed-owner-capability"))
			}
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS:
			cred, e := unix.ParseUnixCredentials(&message)
			if e != nil || credentials || cred.Pid <= 1 || int64(cred.Pid) != int64(peer.pid) || cred.Uid != peer.uid || cred.Gid != peer.gid {
				parseErr = ErrIdentity
			} else {
				credentials = true
			}
		default:
			parseErr = ErrIdentity
		}
	}
	if err != nil || parseErr != nil || !credentials || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 || n > routedDHCPJobFrameV4 || len(files) > 3 || routedPrivateDecodeV4(raw[:n], out) != nil {
		return files, ErrIdentity
	}
	return files, nil
}

type routedDHCPJobOwnerV4 interface {
	TakeReaderFiles() (RoutedDHCPDeferredFilesV4, RoutedDHCPDeferredBindingV4, error)
	Activate(context.Context) error
	Close() error
	Done() <-chan struct{}
}

// Root's dispatcher owns at most one producer. Only its independent preflight
// supplies Desired. Requests carry correlation, never configuration or PIDs.
type routedDHCPJobBrokerV4 struct {
	preflight func(context.Context, configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error)
	prepare   func(context.Context, networkplan.Revision) (routedDHCPJobOwnerV4, error)
	owner     routedDHCPJobOwnerV4
	work      configpoc.RoutedWorkReferenceV1
	desired   string
	active    bool
}

func (b *routedDHCPJobBrokerV4) dispatch(ctx context.Context, q routedDHCPJobV4) (reply routedDHCPJobReplyV4, files []*os.File, result error) {
	reply.Job = q
	if q.Operation == "stop" {
		if b.owner == nil || b.work != q.Work {
			return reply, nil, ErrIdentity
		}
		err := b.owner.Close()
		if err == nil {
			b.owner = nil
			b.work = configpoc.RoutedWorkReferenceV1{}
			b.desired = ""
			b.active = false
		}
		return reply, nil, err
	}
	source, err := b.preflight(ctx, q.Work)
	if err != nil || source.Work != q.Work || source.Resolution != "target" || source.Bundle.Firewall.Config.Routed == nil {
		return reply, nil, ErrIdentity
	}
	desired, err := networkexecutor.CanonicalLANBootstrapPlanV3(source.Bundle.Firewall.Config.Routed.Network)
	if err != nil {
		return reply, nil, ErrIdentity
	}
	switch q.Operation {
	case "prepare":
		if b.owner != nil {
			return reply, nil, ErrIdentity
		}
		owner, e := b.prepare(ctx, desired)
		if e != nil {
			return reply, nil, e
		}
		b.owner, b.work, b.desired = owner, q.Work, desired.Hash
		f, binding, e := owner.TakeReaderFiles()
		if e != nil || binding.Desired.Hash != desired.Hash {
			_ = f.Close()
			return reply, nil, errors.Join(ErrIdentity, owner.Close())
		}
		after, e := b.preflight(ctx, q.Work)
		if e != nil || after.Reference != source.Reference || after.Work != source.Work || after.Resolution != source.Resolution || after.Bundle.Composite.Hash != source.Bundle.Composite.Hash {
			_ = f.Close()
			return reply, nil, errors.Join(ErrIdentity, owner.Close())
		}
		reply.Binding = &binding
		return reply, []*os.File{f.Request, f.Reply, f.ProducerPIDFD}, nil
	case "activate":
		if b.owner == nil || b.active || b.work != q.Work || b.desired != desired.Hash {
			return reply, nil, ErrIdentity
		}
		if err = b.owner.Activate(ctx); err != nil {
			return reply, nil, err
		}
		after, e := b.preflight(ctx, q.Work)
		if e != nil || after.Reference != source.Reference || after.Work != source.Work || after.Resolution != source.Resolution || after.Bundle.Composite.Hash != source.Bundle.Composite.Hash {
			return reply, nil, errors.Join(ErrIdentity, b.owner.Close())
		}
		b.active = true
		return reply, nil, nil
	default:
		return reply, nil, ErrIdentity
	}
}

func (b *routedDHCPJobBrokerV4) serve(ctx context.Context, c *net.UnixConn, m Metadata, peer routedDHCPJobPeerV4) error {
	defer c.Close()
	defer func() {
		if b.owner != nil {
			_ = b.owner.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	var sequence uint64
	for {
		var q routedDHCPJobV4
		files, err := routedDHCPJobReceiveV4(c, peer, &q)
		for _, f := range files {
			_ = f.Close()
		}
		if err != nil || len(files) != 0 || !routedDHCPJobValidV4(q, m, sequence) {
			return ErrIdentity
		}
		sequence = q.Sequence
		call, cancel := context.WithTimeout(ctx, configpoc.IntegrityInspectionDeadlineV1)
		reply, sendFiles, err := b.dispatch(call, q)
		cancel()
		if err != nil {
			reply = routedDHCPJobReplyV4{Job: q, Unavailable: true}
		}
		deadline := time.Now().Add(2 * time.Second)
		writeErr := c.SetWriteDeadline(deadline)
		if writeErr == nil {
			writeErr = routedDHCPJobSendV4(c, reply, sendFiles)
		}
		for _, f := range sendFiles {
			_ = f.Close()
		}
		if err != nil || writeErr != nil {
			return errors.Join(err, writeErr)
		}
	}
}

type routedDHCPJobClientV4 struct {
	mu       sync.Mutex
	conn     *net.UnixConn
	metadata Metadata
	peer     routedDHCPJobPeerV4
	sequence uint64
	failed   bool
}

func (c *routedDHCPJobClientV4) call(ctx context.Context, op string, work configpoc.RoutedWorkReferenceV1) (reply routedDHCPJobReplyV4, returned []*os.File, result error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out routedDHCPJobReplyV4
	if c.failed || ctx == nil || ctx.Err() != nil || c.sequence == math.MaxUint64 {
		return out, nil, ErrUnavailable
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		_ = c.conn.Close()
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
		// Cancellation can race with a valid reply. Drain the close callback and
		// discard every transferred capability before releasing client ownership.
		if ctx.Err() != nil {
			for _, file := range returned {
				_ = file.Close()
			}
			c.failed = true
			_ = c.conn.Close()
			reply, returned, result = routedDHCPJobReplyV4{}, nil, ErrUnavailable
		}
	}()
	c.sequence++
	q := routedDHCPJobV4{4, c.metadata.RunID, c.metadata.GatewayNamespace, c.sequence, op, work}
	deadline := time.Now().Add(configpoc.IntegrityInspectionDeadlineV1)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	fail := func(files []*os.File) (routedDHCPJobReplyV4, []*os.File, error) {
		for _, f := range files {
			_ = f.Close()
		}
		c.failed = true
		_ = c.conn.Close()
		return routedDHCPJobReplyV4{}, nil, ErrUnavailable
	}
	if !routedDHCPJobValidV4(q, c.metadata, c.sequence-1) || c.conn.SetDeadline(deadline) != nil || routedDHCPJobSendV4(c.conn, q, nil) != nil {
		return fail(nil)
	}
	files, err := routedDHCPJobReceiveV4(c.conn, c.peer, &out)
	want := 0
	if op == "prepare" {
		want = 3
	}
	if err != nil || ctx.Err() != nil || out.Job != q || out.Unavailable || len(files) != want || (out.Binding != nil) != (op == "prepare") {
		return fail(files)
	}
	if op == "prepare" && (!routedDHCPDeferredBindingValidV4(*out.Binding) || adoptRoutedDHCPJobPipesV4(files, c.peer) != nil) {
		return fail(files)
	}
	return out, files, nil
}
func (c *routedDHCPJobClientV4) Close() error { return c.conn.Close() }

// SCM_RIGHTS preserves blocking mode. NewFile must see O_NONBLOCK to register
// pipe deadlines; a duplicate avoids two Go finalizers owning the same FD.
// The trusted bootstrap fixes peer UID/GID to root, never reply-supplied IDs.
func adoptRoutedDHCPJobPipesV4(files []*os.File, peer routedDHCPJobPeerV4) error {
	if len(files) != 3 {
		return ErrIdentity
	}
	for i, access := range []int{unix.O_WRONLY, unix.O_RDONLY} {
		if files[i] == nil || files[i].Fd() > math.MaxInt32 {
			return ErrIdentity
		}
		fd := files[i].Fd()
		var st unix.Stat_t
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if err != nil || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Mode&07777 != 0600 || st.Uid != peer.uid || st.Gid != peer.gid || flags&unix.O_ACCMODE != access {
			return ErrIdentity
		}
	}
	for i := 0; i < 2; i++ {
		fd, err := unix.FcntlInt(files[i].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err = unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			return err
		}
		replacement := os.NewFile(uintptr(fd), "routed-owner-pipe")
		if replacement == nil {
			_ = unix.Close(fd)
			return ErrIdentity
		}
		if err = files[i].Close(); err != nil {
			_ = replacement.Close()
			return err
		}
		files[i] = replacement
	}
	return nil
}
