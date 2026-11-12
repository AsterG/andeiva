// Package routedflow observes conntrack in the current network namespace.
// It never applies policy, changes namespaces or processes userspace packets.
package routedflow

import (
	"errors"
	"net/netip"
	"time"
)

const (
	MaxDatagram   = 64 << 10
	MaxDumpBytes  = 4 << 20
	MaxMessages   = 8192
	MaxFlows      = 4096
	MaxAttributes = 256
	DumpTimeout   = 2 * time.Second
)

var (
	ErrObservation = errors.New("ANDEIVA_ROUTED_FLOW_INVALID_OBSERVATION")
	ErrLimit       = errors.New("ANDEIVA_ROUTED_FLOW_LIMIT")
	ErrInterrupted = errors.New("ANDEIVA_ROUTED_FLOW_DUMP_INTERRUPTED")
	ErrUnavailable = errors.New("ANDEIVA_ROUTED_FLOW_UNAVAILABLE")
	ErrPermission  = errors.New("ANDEIVA_ROUTED_FLOW_PERMISSION")
	ErrUnsupported = errors.New("ANDEIVA_ROUTED_FLOW_PLATFORM_UNSUPPORTED")
	ErrTransport   = errors.New("ANDEIVA_ROUTED_FLOW_TRANSPORT")
)

type Endpoint struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
}
type Tuple struct {
	Source         Endpoint `json:"source"`
	Destination    Endpoint `json:"destination"`
	Protocol       string   `json:"protocol"`
	Zone           *uint16  `json:"zone,omitempty"`
	protocolNumber uint8
}
type Counters struct {
	Packets   *uint64 `json:"packets,string,omitempty"`
	Bytes     *uint64 `json:"bytes,string,omitempty"`
	WidthBits uint8   `json:"width_bits"`
}
type TCPState struct {
	Value uint8  `json:"value"`
	Name  string `json:"name"`
}
type Flow struct {
	Original Tuple `json:"original"`
	Reply    Tuple `json:"reply"`
	// ForwardTranslated reverses the kernel reply tuple; ReplyTranslated reverses
	// the original. These are tuple-derived views, not packet capture evidence.
	ForwardTranslated  Tuple     `json:"forward_translated"`
	ReplyTranslated    Tuple     `json:"reply_translated"`
	SourceChanged      bool      `json:"source_changed"`
	DestinationChanged bool      `json:"destination_changed"`
	Status             *uint32   `json:"status,omitempty"`
	Mark               *uint32   `json:"mark,omitempty"`
	ID                 *uint32   `json:"id,omitempty"`
	Zone               *uint16   `json:"zone,omitempty"`
	TimeoutSeconds     *uint32   `json:"timeout_seconds,omitempty"`
	TCPState           *TCPState `json:"tcp_state,omitempty"`
	OriginalCounters   *Counters `json:"original_counters,omitempty"`
	ReplyCounters      *Counters `json:"reply_counters,omitempty"`
}
type Snapshot struct {
	SchemaVersion         int       `json:"schema_version"`
	StartedAt             time.Time `json:"started_at"`
	FinishedAt            time.Time `json:"finished_at"`
	Flows                 []Flow    `json:"flows"`
	SkippedOtherProtocols int       `json:"skipped_other_protocols"`
}

func reverse(t Tuple) Tuple {
	return Tuple{Source: t.Destination, Destination: t.Source, Protocol: t.Protocol}
}
func tcpState(v byte) *TCPState {
	names := []string{"none", "syn_sent", "syn_recv", "established", "fin_wait", "close_wait", "last_ack", "time_wait", "close", "syn_sent2"}
	name := "unknown"
	if int(v) < len(names) {
		name = names[v]
	}
	return &TCPState{Value: v, Name: name}
}
