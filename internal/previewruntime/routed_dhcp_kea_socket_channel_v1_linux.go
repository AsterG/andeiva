//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type routedKeaSocketQueryV1 struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
}

type routedKeaSocketProofV1 struct {
	Query       routedKeaSocketQueryV1 `json:"query"`
	PID         int                    `json:"pid"`
	Start       uint64                 `json:"start,string"`
	Inodes      []uint64               `json:"inodes"`
	Unavailable bool                   `json:"unavailable"`
}

type routedKeaSocketObserverV1 struct {
	mu       sync.Mutex
	conn     *net.UnixConn
	peer     routedDHCPJobPeerV4
	sequence uint64
}

func (s *routedKeaSocketObserverV1) observe(ctx context.Context) (routedKeaSocketProofV1, error) {
	var out routedKeaSocketProofV1
	if s == nil || ctx == nil || ctx.Err() != nil {
		return out, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sequence == math.MaxUint64 || ctx.Err() != nil {
		return out, ErrUnavailable
	}
	deadline := time.Now().Add(routedDHCPOwnerCallV3)
	if end, set := ctx.Deadline(); set && end.Before(deadline) {
		deadline = end
	}
	q := routedKeaSocketQueryV1{Version: 1, Sequence: s.sequence + 1}
	if s.conn.SetDeadline(deadline) != nil || routedDHCPJobSendV4(s.conn, q, nil) != nil {
		_ = s.conn.Close()
		return out, ErrUnavailable
	}
	files, err := routedDHCPJobReceiveV4(s.conn, s.peer, &out)
	for _, f := range files {
		_ = f.Close()
	}
	if err != nil || len(files) != 0 || out.Query != q ||
		(out.Unavailable && (out.PID != 0 || out.Start != 0 || out.Inodes != nil)) ||
		(!out.Unavailable && (out.PID <= 1 || out.PID == s.peer.pid || out.PID > math.MaxInt32 || out.Start == 0 ||
			len(out.Inodes) == 0 || len(out.Inodes) > 256 || out.Inodes[0] == 0 || !slices.IsSorted(out.Inodes))) {
		_ = s.conn.Close()
		return routedKeaSocketProofV1{}, ErrIdentity
	}
	s.sequence = q.Sequence
	if out.Unavailable || ctx.Err() != nil {
		return routedKeaSocketProofV1{}, ErrUnavailable
	}
	return out, nil
}

// The role owns both its engine pidfd and the isolated credentials needed to
// sample custody. The supervisor can request a read only through this channel.
func serveRoutedKeaSocketProofV1(ctx context.Context, conn *net.UnixConn, peer routedDHCPJobPeerV4, engine *os.File, identity routedKeaEngineIdentityV1) error {
	defer conn.Close()
	defer engine.Close()
	// Interrupt the idle receive without closing the socket during a bounded
	// reply. Shutdown leaves validation and transport errors distinguishable.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var last uint64
	for ctx.Err() == nil {
		var q routedKeaSocketQueryV1
		files, err := receiveRoutedDHCPJobFrameV4(conn, peer, &q)
		for _, f := range files {
			_ = f.Close()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || len(files) != 0 || q.Version != 1 || last == math.MaxUint64 || q.Sequence != last+1 {
			return ErrIdentity
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		last = q.Sequence
		inodes, err := readRoutedKeaEngineSocketHoldersV1(engine, identity)
		proof := routedKeaSocketProofV1{Query: q, Unavailable: err != nil}
		if err == nil {
			proof.PID, proof.Start, proof.Inodes = identity.pid, identity.start, inodes
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if conn.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPJobSendV4(conn, proof, nil) != nil {
			return ErrUnavailable
		}
	}
	return ctx.Err()
}

func routedKeaSocketEngineV1(fd int, pid int, uid, gid uint32, namespace uint64) (*os.File, routedKeaEngineIdentityV1, error) {
	start, parent, err := routedDHCPOwnerProcessV3(pid)
	if err != nil || parent != os.Getpid() {
		return nil, routedKeaEngineIdentityV1{}, ErrIdentity
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, routedKeaEngineIdentityV1{}, ErrIdentity
	}
	pin := os.NewFile(uintptr(duplicate), "kea-engine-proof-pidfd")
	if !routedDHCPOwnerPIDFDAliveV3(pin, pid) {
		_ = pin.Close()
		return nil, routedKeaEngineIdentityV1{}, ErrIdentity
	}
	return pin, routedKeaEngineIdentityV1{pid: pid, parent: parent, start: start, namespace: namespace, uid: uid, gid: gid}, nil
}
