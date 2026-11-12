package routedflow

import (
	"context"
	"time"
)

type datagram struct {
	data                 []byte
	peerPort, peerGroups uint32
	truncated            bool
}
type transport interface {
	send(context.Context, []byte) error
	receive(context.Context) (datagram, error)
}

func collect(parent context.Context, t transport, sequence, port uint32) (Snapshot, error) {
	if parent == nil || t == nil || sequence == 0 || port == 0 {
		return Snapshot{}, ErrObservation
	}
	ctx, cancel := context.WithTimeout(parent, DumpTimeout)
	defer cancel()
	started := time.Now().UTC()
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if e := t.send(ctx, dumpRequest(sequence, port)); e != nil {
		return Snapshot{}, e
	}
	decoder := newMultipart(sequence, port)
	for !decoder.done {
		if e := ctx.Err(); e != nil {
			return Snapshot{}, e
		}
		packet, e := t.receive(ctx)
		if e != nil {
			return Snapshot{}, e
		}
		if e := ctx.Err(); e != nil {
			return Snapshot{}, e
		}
		if e = decoder.consume(packet.data, packet.peerPort, packet.peerGroups, packet.truncated); e != nil {
			return Snapshot{}, e
		}
	}
	return Snapshot{SchemaVersion: 1, StartedAt: started, FinishedAt: time.Now().UTC(), Flows: decoder.flows, SkippedOtherProtocols: decoder.skipped}, nil
}
