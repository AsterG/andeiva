//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const continuityLimitV4 = 8192 // Covers 195s at 40Hz or the fixed 650s at 10Hz profile.
const continuityJSONLimitV4 = 1 << 20
const continuityCheckpointLimitV4 = 8

// Fixed laboratory profiles only: neither duration nor probe rate is caller input.
type continuityProfileV4 uint8

const (
	continuityDefaultV4     continuityProfileV4 = 0
	continuityTenRenewalsV4 continuityProfileV4 = 10
)

func (p continuityProfileV4) limits() (window, interval time.Duration, valid bool) {
	switch p {
	case continuityDefaultV4:
		return 195 * time.Second, 25 * time.Millisecond, true
	case continuityTenRenewalsV4:
		return 650 * time.Second, 100 * time.Millisecond, true
	default:
		return 0, 0, false
	}
}

func continuityProfileFromEnvironmentV4(value string) (continuityProfileV4, bool) {
	switch value {
	case "", "0":
		return continuityDefaultV4, true
	case "10":
		return continuityTenRenewalsV4, true
	default:
		return 0, false
	}
}

var errContinuityProtocolV4 = errors.New("invalid private continuity protocol")

type continuitySetV4 [continuityLimitV4 / 64]uint64

func (s *continuitySetV4) has(seq uint64) bool {
	return seq > 0 && seq <= continuityLimitV4 && s[(seq-1)/64]&(uint64(1)<<((seq-1)%64)) != 0
}
func (s *continuitySetV4) add(seq uint64) { s[(seq-1)/64] |= uint64(1) << ((seq - 1) % 64) }
func (s continuitySetV4) count() uint64 {
	var n uint64
	for _, v := range s {
		n += uint64(bits.OnesCount64(v))
	}
	return n
}
func (s continuitySetV4) subset(other continuitySetV4) bool {
	for i, v := range s {
		if v & ^other[i] != 0 {
			return false
		}
	}
	return true
}

type nativeDHCPContinuityGapV4 struct {
	BeforeBootNS int64 `json:"before_boot_ns"`
	AfterBootNS  int64 `json:"after_boot_ns"`
	IntervalNS   int64 `json:"interval_ns"`
}
type nativeDHCPContinuityMissingV4 struct {
	Sequence   uint64 `json:"sequence"`
	SentBootNS int64  `json:"sent_boot_ns"`
}
type nativeDHCPContinuitySampleV4 struct {
	Sequence   uint64 `json:"sequence"`
	SentBootNS int64  `json:"sent_boot_ns"`
	EchoBootNS int64  `json:"echo_boot_ns"`
}
type nativeDHCPContinuityCheckpointV4 struct {
	ID          uint64                       `json:"id"`
	AfterBootNS int64                        `json:"after_boot_ns"`
	TCP         nativeDHCPContinuitySampleV4 `json:"tcp"`
	UDP         nativeDHCPContinuitySampleV4 `json:"udp"`
}

// Counts describe application datagrams observed before the bounded drain ends,
// not exact kernel packet loss. TCP retransmissions are separate TCP_INFO data.
// ICMP counters mean compatible socket errnos, without packet capture.
type nativeDHCPContinuityReportV4 struct {
	Stopped               bool                            `json:"stopped"`
	TCPAccepted           uint64                          `json:"tcp_accepted"`
	TCPSent               uint64                          `json:"tcp_sent_messages"`
	TCPEchoed             uint64                          `json:"tcp_echoed_messages"`
	TCPDisconnects        uint64                          `json:"tcp_disconnects"`
	TCPInfoAvailable      bool                            `json:"tcp_info_available"`
	TCPTotalRetrans       uint32                          `json:"tcp_total_retrans"`
	TCPFirstEchoBootNS    int64                           `json:"tcp_first_echo_boot_ns"`
	TCPLastEchoBootNS     int64                           `json:"tcp_last_echo_boot_ns"`
	TCPSource             string                          `json:"tcp_source"`
	TCPDestination        string                          `json:"tcp_destination"`
	TCPSinkTuple          string                          `json:"tcp_sink_tuple"`
	UDPSource             string                          `json:"udp_source"`
	UDPDestination        string                          `json:"udp_destination"`
	UDPSinkTuple          string                          `json:"udp_sink_tuple"`
	UDPTupleChanges       uint64                          `json:"udp_tuple_changes"`
	UDPWriteAttempts      uint64                          `json:"udp_write_attempts"`
	UDPSent               uint64                          `json:"udp_sent_datagrams"`
	UDPSendErrors         uint64                          `json:"udp_send_errors"`
	UDPReadICMP           uint64                          `json:"udp_read_icmp_compatible_errors"`
	UDPWriteICMP          uint64                          `json:"udp_write_icmp_compatible_errors"`
	UDPUniqueEchoes       uint64                          `json:"udp_unique_echoes"`
	UDPMissingEchoes      uint64                          `json:"udp_missing_echoes"`
	UDPDuplicates         uint64                          `json:"udp_duplicate_echoes"`
	UDPInvalid            uint64                          `json:"udp_invalid_echoes"`
	FirstEchoBootNS       int64                           `json:"first_echo_boot_ns"`
	LastEchoBootNS        int64                           `json:"last_echo_boot_ns"`
	Gaps                  []nativeDHCPContinuityGapV4     `json:"observable_echo_gaps"`
	GapsTruncated         bool                            `json:"gaps_truncated"`
	Missing               []nativeDHCPContinuityMissingV4 `json:"missing_echo_probes"`
	MissingTruncated      bool                            `json:"missing_echo_probes_truncated"`
	UDPSentSet            continuitySetV4                 `json:"udp_sent_set"`
	UDPSendStartBootNS    [continuityLimitV4 + 1]int64    `json:"udp_send_start_boot_ns"`
	UDPSendEndBootNS      [continuityLimitV4 + 1]int64    `json:"udp_send_end_boot_ns"`
	UDPEchoSet            continuitySetV4                 `json:"udp_echo_set"`
	UDPSinkReceived       uint64                          `json:"udp_sink_received_datagrams"`
	UDPSinkUniqueReceived uint64                          `json:"udp_sink_unique_received"`
	UDPSinkEchoWrites     uint64                          `json:"udp_sink_echo_writes"`
	UDPSinkUniqueReplied  uint64                          `json:"udp_sink_unique_replied"`
	UDPReplyErrors        uint64                          `json:"udp_reply_errors"`
	UDPReplyICMP          uint64                          `json:"udp_reply_icmp_compatible_errors"`
	UDPSinkReadICMP       uint64                          `json:"udp_sink_read_icmp_compatible_errors"`
	UDPSinkReceivedSet    continuitySetV4                 `json:"udp_sink_received_set"`
	UDPSinkRepliedSet     continuitySetV4                 `json:"udp_sink_replied_set"`
	UDPRequestMissing     uint64                          `json:"udp_requests_not_observed_at_sink"`
	UDPReplyMissing       uint64                          `json:"udp_replies_not_observed_at_source"`
	UDPSinkUnanswered     uint64                          `json:"udp_received_without_successful_reply"`
	Error                 string                          `json:"error,omitempty"`
}

type continuityFrameV4 struct {
	Version    int                               `json:"version"`
	Kind       string                            `json:"kind"`
	Checkpoint *nativeDHCPContinuityCheckpointV4 `json:"checkpoint,omitempty"`
	Report     *nativeDHCPContinuityReportV4     `json:"report,omitempty"`
}
type continuityCommandV4 struct {
	Version     int    `json:"version"`
	Operation   string `json:"operation"`
	ID          uint64 `json:"id"`
	AfterBootNS int64  `json:"after_boot_ns"`
}

// Require exact members, unique lower-case keys and one JSON value. Null cannot
// hide a mandatory member. Arrays are additionally checked by report invariants.
func continuityDecodeV4(raw []byte, into any) error {
	if len(raw) == 0 || len(raw) > continuityJSONLimitV4 || !jsoncheck.UniqueControlFields(raw) {
		return errContinuityProtocolV4
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil {
		return errContinuityProtocolV4
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errContinuityProtocolV4
	}
	canonical, err := json.Marshal(into)
	if err != nil {
		return err
	}
	var expected, observed map[string]json.RawMessage
	if json.Unmarshal(canonical, &expected) != nil || json.Unmarshal(raw, &observed) != nil || len(expected) != len(observed) {
		return errContinuityProtocolV4
	}
	for key, want := range expected {
		got, ok := observed[key]
		if !ok || !continuitySameShapeV4(want, got) {
			return errContinuityProtocolV4
		}
	}
	return nil
}
func continuitySameShapeV4(expected, observed []byte) bool {
	if len(expected) > 0 && expected[0] == '[' {
		var a, b []json.RawMessage
		if json.Unmarshal(expected, &a) != nil || json.Unmarshal(observed, &b) != nil || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !continuitySameShapeV4(a[i], b[i]) {
				return false
			}
		}
	}
	if len(expected) > 0 && expected[0] == '{' {
		var a, b map[string]json.RawMessage
		if json.Unmarshal(expected, &a) != nil || json.Unmarshal(observed, &b) != nil || len(a) != len(b) {
			return false
		}
		for key, value := range a {
			other, ok := b[key]
			if !ok || !continuitySameShapeV4(value, other) {
				return false
			}
		}
	}
	return !bytes.Equal(bytes.TrimSpace(observed), []byte("null")) || bytes.Equal(expected, []byte("null"))
}
func continuityTupleV4(value, ip string, port uint16) bool {
	a, err := netip.ParseAddrPort(value)
	return err == nil && a.Addr().Is4() && !a.Addr().IsUnspecified() && (ip == "" || a.Addr().String() == ip) && (port == 0 && a.Port() > 0 || a.Port() == port)
}
func continuityReportValidV4(role string, r nativeDHCPContinuityReportV4) bool {
	if !r.Stopped || r.Error != "" || r.UDPInvalid != 0 || len(r.Missing) > continuityLimitV4 || r.MissingTruncated || len(r.Gaps) > 256 || r.TCPDisconnects != 0 || r.TCPSent > continuityLimitV4 || r.TCPEchoed > r.TCPSent || r.TCPSent-r.TCPEchoed > 1 {
		return false
	}
	if r.UDPWriteAttempts > continuityLimitV4 || r.UDPSendErrors > continuityLimitV4 || r.UDPWriteAttempts != r.UDPSent+r.UDPSendErrors || r.UDPWriteICMP > r.UDPSendErrors || r.UDPSent != r.UDPSentSet.count() || r.UDPUniqueEchoes != r.UDPEchoSet.count() || !r.UDPEchoSet.subset(r.UDPSentSet) || r.UDPMissingEchoes != r.UDPSent-r.UDPUniqueEchoes || uint64(len(r.Missing)) != r.UDPMissingEchoes {
		return false
	}
	var previousEnd int64
	for seq := uint64(0); seq <= continuityLimitV4; seq++ {
		start, end := r.UDPSendStartBootNS[seq], r.UDPSendEndBootNS[seq]
		if r.UDPSentSet.has(seq) {
			if start <= 0 || end < start || start < previousEnd {
				return false
			}
			previousEnd = end
		} else if start != 0 || end != 0 {
			return false
		}
	}
	var missing continuitySetV4
	for _, p := range r.Missing {
		if !r.UDPSentSet.has(p.Sequence) || r.UDPEchoSet.has(p.Sequence) || missing.has(p.Sequence) || p.SentBootNS <= 0 || p.SentBootNS != r.UDPSendStartBootNS[p.Sequence] {
			return false
		}
		missing.add(p.Sequence)
	}
	var previousGap int64
	for _, g := range r.Gaps {
		if g.BeforeBootNS < r.FirstEchoBootNS || g.BeforeBootNS < previousGap || g.AfterBootNS > r.LastEchoBootNS || g.BeforeBootNS <= 0 || g.AfterBootNS <= g.BeforeBootNS || g.IntervalNS != g.AfterBootNS-g.BeforeBootNS {
			return false
		}
		previousGap = g.AfterBootNS
	}
	if len(r.Gaps) > 0 && uint64(len(r.Gaps)) >= r.UDPUniqueEchoes || r.TCPEchoed == 1 && r.TCPFirstEchoBootNS != r.TCPLastEchoBootNS || r.UDPUniqueEchoes == 1 && r.FirstEchoBootNS != r.LastEchoBootNS {
		return false
	}
	if r.UDPSinkReceived > continuityLimitV4*16 || r.UDPSinkEchoWrites > continuityLimitV4*16 || r.UDPReplyErrors > continuityLimitV4*16 || r.UDPDuplicates > continuityLimitV4*16 || r.UDPReadICMP > continuityLimitV4*16 || r.UDPSinkReadICMP > continuityLimitV4*16 || r.UDPSinkUniqueReceived != r.UDPSinkReceivedSet.count() || r.UDPSinkUniqueReplied != r.UDPSinkRepliedSet.count() || !r.UDPSinkRepliedSet.subset(r.UDPSinkReceivedSet) || r.UDPSinkUniqueReceived > r.UDPSinkReceived || r.UDPSinkUniqueReplied > r.UDPSinkEchoWrites || r.UDPSinkReceived != r.UDPSinkEchoWrites+r.UDPReplyErrors || r.UDPReplyICMP > r.UDPReplyErrors {
		return false
	}
	if role == "source" {
		return r.TCPEchoed > 0 && r.TCPFirstEchoBootNS > 0 && r.TCPLastEchoBootNS >= r.TCPFirstEchoBootNS && r.UDPUniqueEchoes > 0 && r.FirstEchoBootNS > 0 && r.LastEchoBootNS >= r.FirstEchoBootNS && continuityTupleV4(r.TCPSource, "198.18.0.2", 0) && continuityTupleV4(r.TCPDestination, "198.18.1.1", 18080) && continuityTupleV4(r.UDPSource, "198.18.0.2", 0) && continuityTupleV4(r.UDPDestination, "198.18.1.1", 18081) && r.TCPAccepted == 0 && r.UDPSinkReceived == 0
	}
	return role == "sink" && r.TCPAccepted == 1 && r.UDPTupleChanges == 0 && r.UDPSinkUniqueReceived > 0 && continuityTupleV4(r.TCPSinkTuple, "", 0) && continuityTupleV4(r.UDPSinkTuple, "", 0) && r.TCPSent == 0 && r.UDPSent == 0
}
func continuityCheckpointValidV4(a nativeDHCPContinuityCheckpointV4) bool {
	if a.ID == 0 || a.AfterBootNS <= 0 {
		return false
	}
	for _, p := range []nativeDHCPContinuitySampleV4{a.TCP, a.UDP} {
		if p.Sequence == 0 || p.Sequence > continuityLimitV4 || p.SentBootNS <= a.AfterBootNS || p.EchoBootNS < p.SentBootNS {
			return false
		}
	}
	return true
}

type continuityProtocolV4 struct {
	role                        string
	ready, final, stopRequested bool
	pendingID                   uint64
	pendingAfter                int64
	lastCheckpoint              *nativeDHCPContinuityCheckpointV4
	report                      nativeDHCPContinuityReportV4
}

func (p *continuityProtocolV4) accept(raw []byte) (continuityFrameV4, error) {
	var f continuityFrameV4
	if continuityDecodeV4(raw, &f) != nil || f.Version != 1 || p.final {
		return f, errContinuityProtocolV4
	}
	switch f.Kind {
	case "ready":
		if p.ready || f.Report != nil || f.Checkpoint != nil {
			return f, errContinuityProtocolV4
		}
		p.ready = true
	case "checkpoint":
		a := f.Checkpoint
		if !p.ready || p.role != "source" || f.Report != nil || a == nil || a.ID != p.pendingID || a.AfterBootNS != p.pendingAfter || !continuityCheckpointValidV4(*a) {
			return f, errContinuityProtocolV4
		}
		p.pendingID = 0
		p.lastCheckpoint = a
	case "report":
		if f.Report == nil || f.Checkpoint != nil {
			return f, errContinuityProtocolV4
		}
		if f.Report.Error != "" {
			if len(f.Report.Error) > 256 {
				return f, errContinuityProtocolV4
			}
			return f, errors.New(f.Report.Error)
		}
		if !p.ready || !p.stopRequested || p.pendingID != 0 || !continuityReportValidV4(p.role, *f.Report) {
			return f, errContinuityProtocolV4
		}
		if a := p.lastCheckpoint; a != nil && (f.Report.TCPEchoed < a.TCP.Sequence || !f.Report.UDPEchoSet.has(a.UDP.Sequence) || f.Report.TCPLastEchoBootNS < a.TCP.EchoBootNS || f.Report.LastEchoBootNS < a.UDP.EchoBootNS) {
			return f, errContinuityProtocolV4
		}
		p.report = *f.Report
		p.final = true
	default:
		return f, errContinuityProtocolV4
	}
	return f, nil
}
func readContinuityFramesV4(reader io.Reader, accept func([]byte) error) error {
	limited := &io.LimitedReader{R: reader, N: continuityJSONLimitV4 + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), continuityJSONLimitV4+1)
	for scanner.Scan() {
		if err := accept(scanner.Bytes()); err != nil {
			return err
		}
	}
	if scanner.Err() != nil || limited.N <= 0 {
		return errors.Join(errContinuityProtocolV4, scanner.Err())
	}
	return nil
}

type continuityChildV4 struct {
	input         io.WriteCloser
	cancel        context.CancelFunc
	done, ready   chan struct{}
	acks          chan nativeDHCPContinuityCheckpointV4
	mu, operation sync.Mutex
	protocol      continuityProtocolV4
	nextID        uint64
	result        nativeDHCPContinuityReportV4
	err           error
}
type nativeDHCPContinuityV4 struct {
	source, sink *continuityChildV4
	once         sync.Once
	report       nativeDHCPContinuityReportV4
	err          error
}

func startNativeDHCPContinuityV4(t *testing.T, ctx context.Context, source, sink *os.File) (*nativeDHCPContinuityV4, error) {
	return startNativeDHCPContinuityProfileV4(t, ctx, source, sink, continuityDefaultV4)
}

func startNativeDHCPContinuityProfileV4(t *testing.T, ctx context.Context, source, sink *os.File, profile continuityProfileV4) (*nativeDHCPContinuityV4, error) {
	t.Helper()
	_, _, valid := profile.limits()
	if !valid || ctx == nil || os.Getenv("ANDEIVA_NATIVE_DHCP_JOBS_V4") != "1" || os.Geteuid() != 0 || os.Getenv("CI") != "" {
		return nil, errors.New("isolated native laboratory only")
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil {
		return nil, errors.New("untrusted fixture executable")
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	var previous os.FileInfo
	for _, ns := range []*os.File{source, sink} {
		if ns == nil {
			return nil, errors.New("missing pinned network namespace")
		}
		kind, e := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_NSTYPE)
		info, statErr := ns.Stat()
		if e != nil || kind != unix.CLONE_NEWNET || statErr != nil || os.SameFile(current, info) || previous != nil && os.SameFile(previous, info) {
			return nil, errors.New("non-isolated network namespace")
		}
		previous = info
	}
	h := &nativeDHCPContinuityV4{}
	h.sink, err = startContinuityChildV4(ctx, self, "sink", sink, profile)
	if err != nil {
		return nil, err
	}
	h.source, err = startContinuityChildV4(ctx, self, "source", source, profile)
	if err != nil {
		_, _ = stopContinuityChildV4(h.sink)
		return nil, err
	}
	t.Cleanup(func() {
		if _, err := h.Stop(); err != nil {
			t.Errorf("continuity cleanup: %v", err)
		}
	})
	return h, nil
}
func (h *nativeDHCPContinuityV4) Checkpoint(ctx context.Context, afterBootNS int64) (nativeDHCPContinuityCheckpointV4, error) {
	var empty nativeDHCPContinuityCheckpointV4
	if h == nil || ctx == nil || ctx.Err() != nil || afterBootNS <= 0 {
		return empty, errContinuityProtocolV4
	}
	c := h.source
	if !c.operation.TryLock() {
		return empty, errors.New("another continuity operation is pending")
	}
	defer c.operation.Unlock()
	c.mu.Lock()
	if c.protocol.stopRequested || !c.protocol.ready || c.nextID >= continuityCheckpointLimitV4 {
		c.mu.Unlock()
		return empty, errContinuityProtocolV4
	}
	c.nextID++
	id := c.nextID
	c.protocol.pendingID = id
	c.protocol.pendingAfter = afterBootNS
	c.mu.Unlock()
	if err := c.write(continuityCommandV4{1, "checkpoint", id, afterBootNS}); err != nil {
		c.cancel()
		<-c.done
		return empty, errors.Join(err, c.err)
	}
	select {
	case ack := <-c.acks:
		if ctx.Err() != nil {
			c.cancel()
			<-c.done
			return empty, errors.Join(ctx.Err(), c.err)
		}
		return ack, nil
	case <-c.done:
		return empty, errors.Join(errors.New("continuity ended before checkpoint"), c.err)
	case <-ctx.Done():
		c.cancel()
		<-c.done
		return empty, errors.Join(ctx.Err(), c.err)
	}
}
func (h *nativeDHCPContinuityV4) Stop() (nativeDHCPContinuityReportV4, error) {
	h.once.Do(func() {
		source, sourceErr := stopContinuityChildV4(h.source)
		sink, sinkErr := stopContinuityChildV4(h.sink)
		source.TCPAccepted, source.TCPSinkTuple = sink.TCPAccepted, sink.TCPSinkTuple
		source.UDPSinkTuple, source.UDPTupleChanges = sink.UDPSinkTuple, sink.UDPTupleChanges
		source.UDPSinkReceived, source.UDPSinkUniqueReceived = sink.UDPSinkReceived, sink.UDPSinkUniqueReceived
		source.UDPSinkEchoWrites, source.UDPSinkUniqueReplied = sink.UDPSinkEchoWrites, sink.UDPSinkUniqueReplied
		source.UDPReplyErrors, source.UDPReplyICMP, source.UDPSinkReadICMP = sink.UDPReplyErrors, sink.UDPReplyICMP, sink.UDPSinkReadICMP
		source.UDPSinkReceivedSet, source.UDPSinkRepliedSet = sink.UDPSinkReceivedSet, sink.UDPSinkRepliedSet
		if sourceErr == nil && sinkErr == nil {
			sourceErr = continuityDirectionsV4(&source)
		}
		h.report, h.err = source, errors.Join(sourceErr, sinkErr)
	})
	return h.report, h.err
}
func continuityDirectionsV4(r *nativeDHCPContinuityReportV4) error {
	if r.UDPSent != r.UDPSentSet.count() || r.UDPUniqueEchoes != r.UDPEchoSet.count() || r.UDPSinkUniqueReceived != r.UDPSinkReceivedSet.count() || r.UDPSinkUniqueReplied != r.UDPSinkRepliedSet.count() || !r.UDPSinkReceivedSet.subset(r.UDPSentSet) || !r.UDPSinkRepliedSet.subset(r.UDPSinkReceivedSet) || !r.UDPEchoSet.subset(r.UDPSinkRepliedSet) {
		return errors.New("inconsistent directional UDP observations")
	}
	r.UDPRequestMissing = r.UDPSent - r.UDPSinkUniqueReceived
	r.UDPReplyMissing = r.UDPSinkUniqueReplied - r.UDPUniqueEchoes
	r.UDPSinkUnanswered = r.UDPSinkUniqueReceived - r.UDPSinkUniqueReplied
	if r.UDPMissingEchoes != r.UDPRequestMissing+r.UDPReplyMissing+r.UDPSinkUnanswered {
		return errContinuityProtocolV4
	}
	return nil
}
func (c *continuityChildV4) write(command continuityCommandV4) error {
	if d, ok := c.input.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := d.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
	}
	return json.NewEncoder(c.input).Encode(command)
}
func startContinuityChildV4(parent context.Context, self, role string, namespace *os.File, profile continuityProfileV4) (*continuityChildV4, error) {
	window, _, valid := profile.limits()
	if !valid {
		return nil, errContinuityProtocolV4
	}
	ctx, cancel := context.WithTimeout(parent, window+5*time.Second)
	parentNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		cancel()
		return nil, err
	}
	reportR, reportW, err := os.Pipe()
	if err != nil {
		parentNS.Close()
		cancel()
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", self, "-test.run=^TestNativeDHCPContinuityRoleV4$", "-test.count=1", "-test.timeout="+(window+10*time.Second).String())
	cmd.ExtraFiles = []*os.File{namespace, parentNS, reportW}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "ANDEIVA_NATIVE_DHCP_JOBS_V4=1", "ANDEIVA_CONTINUITY_ROLE_V4=" + role}
	if profile == continuityTenRenewalsV4 {
		cmd.Env = append(cmd.Env, "ANDEIVA_CONTINUITY_PROFILE_V4=10")
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	input, err := cmd.StdinPipe()
	if err != nil {
		parentNS.Close()
		reportR.Close()
		reportW.Close()
		cancel()
		return nil, err
	}
	c := &continuityChildV4{input: input, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), acks: make(chan nativeDHCPContinuityCheckpointV4, 1), protocol: continuityProtocolV4{role: role}}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(c.done)
		defer reportR.Close()
		err := cmd.Start()
		parentNS.Close()
		reportW.Close()
		if err != nil {
			c.err = err
			return
		}
		parseErr := readContinuityFramesV4(reportR, func(raw []byte) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			frame, err := c.protocol.accept(raw)
			if err != nil {
				return err
			}
			switch frame.Kind {
			case "ready":
				close(c.ready)
			case "checkpoint":
				c.acks <- *frame.Checkpoint
			}
			return nil
		})
		if parseErr != nil {
			cancel()
		}
		waitErr := cmd.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.protocol.final {
			parseErr = errors.Join(parseErr, errors.New("missing final continuity report"))
		}
		c.result, c.err = c.protocol.report, errors.Join(parseErr, waitErr)
	}()
	select {
	case <-c.ready:
		return c, nil
	case <-c.done:
		input.Close()
		cancel()
		return nil, errors.Join(errors.New("continuity child not ready"), c.err)
	case <-time.After(8 * time.Second):
		_, err := stopContinuityChildV4(c)
		return nil, errors.Join(errors.New("continuity startup timeout"), err)
	case <-ctx.Done():
		_, err := stopContinuityChildV4(c)
		return nil, errors.Join(ctx.Err(), err)
	}
}
func stopContinuityChildV4(c *continuityChildV4) (nativeDHCPContinuityReportV4, error) {
	c.operation.Lock()
	defer c.operation.Unlock()
	defer c.cancel()
	select {
	case <-c.done:
		c.input.Close()
		return c.result, c.err
	default:
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.protocol.stopRequested = true
	c.mu.Unlock()
	writeErr := c.write(continuityCommandV4{1, "stop", id, 0})
	c.input.Close()
	if writeErr != nil {
		c.cancel()
	}
	select {
	case <-c.done:
		return c.result, errors.Join(writeErr, c.err)
	case <-time.After(4 * time.Second):
		c.cancel()
		<-c.done
		return c.result, errors.Join(errors.New("continuity shutdown timeout"), writeErr, c.err)
	}
}

type continuityStateV4 struct {
	mu          sync.Mutex
	profile     continuityProfileV4
	role        string
	report      nativeDHCPContinuityReportV4
	sentAt      [continuityLimitV4 + 1]int64
	sentEndAt   [continuityLimitV4 + 1]int64
	tcp, udp    nativeDHCPContinuitySampleV4
	pending     *nativeDHCPContinuityCheckpointV4
	advertised  bool
	nextCommand uint64
	failure     error
	cancel      context.CancelFunc
	emit        func(continuityFrameV4) error
	now         func() (int64, error)
}

func (s *continuityStateV4) failLocked(err error) {
	if s.failure == nil {
		s.failure = err
	}
	s.cancel()
}
func (s *continuityStateV4) observeLocked() {
	if !s.advertised && (s.role == "sink" || s.report.TCPEchoed > 0 && s.report.UDPUniqueEchoes > 0) {
		s.advertised = true
		if err := s.emit(continuityFrameV4{Version: 1, Kind: "ready"}); err != nil {
			s.failLocked(err)
			return
		}
	}
	if s.pending != nil && s.tcp.SentBootNS > s.pending.AfterBootNS && s.tcp.EchoBootNS >= s.tcp.SentBootNS && s.udp.SentBootNS > s.pending.AfterBootNS && s.udp.EchoBootNS >= s.udp.SentBootNS {
		ack := *s.pending
		ack.TCP, ack.UDP = s.tcp, s.udp
		s.pending = nil
		if err := s.emit(continuityFrameV4{Version: 1, Kind: "checkpoint", Checkpoint: &ack}); err != nil {
			s.failLocked(err)
		}
	}
}
func (s *continuityStateV4) echoLocked(seq uint64, boot int64) {
	if !s.report.UDPSentSet.has(seq) || boot < s.sentAt[seq] || boot <= 0 {
		s.report.UDPInvalid++
		s.failLocked(errors.New("UDP echo was never successfully sent"))
		return
	}
	if s.report.UDPEchoSet.has(seq) {
		s.report.UDPDuplicates++
		if s.report.UDPDuplicates > continuityLimitV4*16 {
			s.failLocked(errors.New("too many duplicate UDP echoes"))
		}
		return
	}
	s.report.UDPEchoSet.add(seq)
	s.report.UDPUniqueEchoes++
	if s.report.FirstEchoBootNS == 0 {
		s.report.FirstEchoBootNS = boot
	}
	_, interval, _ := s.profile.limits()
	if prior := s.report.LastEchoBootNS; prior > 0 && boot-prior > int64(3*interval) {
		if len(s.report.Gaps) < 256 {
			s.report.Gaps = append(s.report.Gaps, nativeDHCPContinuityGapV4{prior, boot, boot - prior})
		} else {
			s.report.GapsTruncated = true
		}
	}
	s.report.LastEchoBootNS = boot
	if s.sentAt[seq] > s.udp.SentBootNS {
		s.udp = nativeDHCPContinuitySampleV4{seq, s.sentAt[seq], boot}
	}
	s.observeLocked()
}
func (s *continuityStateV4) snapshot() nativeDHCPContinuityReportV4 {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.report
	if s.role == "source" {
		r.UDPSendStartBootNS, r.UDPSendEndBootNS = s.sentAt, s.sentEndAt
		r.UDPMissingEchoes = r.UDPSent - r.UDPUniqueEchoes
		for seq := uint64(1); seq <= continuityLimitV4; seq++ {
			if r.UDPSentSet.has(seq) && !r.UDPEchoSet.has(seq) {
				r.Missing = append(r.Missing, nativeDHCPContinuityMissingV4{seq, s.sentAt[seq]})
			}
		}
	}
	if s.failure != nil {
		r.Error = s.failure.Error()
	}
	return r
}
func continuityTransientUDPV4(err error) bool {
	// EACCES can also be local policy denial. These counters identify compatible
	// errno observations, never captured ICMP packets.
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EACCES)
}
func (s *continuityStateV4) pause(ctx context.Context) bool {
	_, interval, valid := s.profile.limits()
	if !valid {
		return false
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (s *continuityStateV4) sendUDP(ctx context.Context, write func([]byte) (int, error)) {
	var frame [8]byte
	for seq := uint64(1); seq <= continuityLimitV4; seq++ {
		if !s.pause(ctx) {
			return
		}
		binary.BigEndian.PutUint64(frame[:], seq)
		s.mu.Lock() // Commit successful writes before the reader validates an echo.
		if ctx.Err() != nil || s.report.Stopped {
			s.mu.Unlock()
			return
		}
		boot, err := s.now()
		if err != nil {
			s.failLocked(err)
			s.mu.Unlock()
			return
		}
		s.report.UDPWriteAttempts++
		n, err := write(frame[:])
		if err != nil || n != 8 {
			s.report.UDPSendErrors++
			if n == 0 && continuityTransientUDPV4(err) {
				s.report.UDPWriteICMP++
				s.mu.Unlock()
				continue
			}
			if ctx.Err() == nil {
				s.failLocked(errors.New("UDP write failed or was ambiguous"))
			}
			s.mu.Unlock()
			return
		}
		s.report.UDPSent++
		s.report.UDPSentSet.add(seq)
		s.sentAt[seq] = boot
		completed, clockErr := s.now()
		if clockErr != nil || completed < boot {
			s.failLocked(errors.New("UDP send completion clock unavailable"))
			s.mu.Unlock()
			return
		}
		s.sentEndAt[seq] = completed
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.failLocked(errors.New("UDP probe bound exhausted"))
	s.mu.Unlock()
}
func (s *continuityStateV4) readUDP(ctx context.Context, read func([]byte) (int, error)) {
	var frame [9]byte
	for {
		n, err := read(frame[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if continuityTransientUDPV4(err) {
				s.mu.Lock()
				s.report.UDPReadICMP++
				excess := s.report.UDPReadICMP > continuityLimitV4*16
				if excess {
					s.failLocked(errors.New("too many UDP socket errors"))
				}
				s.mu.Unlock()
				if excess || !s.pause(ctx) {
					return
				}
				continue
			}
			s.mu.Lock()
			s.failLocked(errors.New("UDP read failed"))
			s.mu.Unlock()
			return
		}
		boot, err := s.now()
		s.mu.Lock()
		if err != nil || n != 8 {
			s.report.UDPInvalid++
			s.failLocked(errors.New("malformed UDP echo"))
			s.mu.Unlock()
			return
		}
		s.echoLocked(binary.BigEndian.Uint64(frame[:8]), boot)
		failed := s.failure != nil
		s.mu.Unlock()
		if failed {
			return
		}
	}
}
func readContinuityControlsV4(input io.Reader, s *continuityStateV4) error {
	limited := &io.LimitedReader{R: input, N: 4097}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 256), 2048)
	for scan.Scan() {
		var command continuityCommandV4
		if continuityDecodeV4(scan.Bytes(), &command) != nil || command.Version != 1 {
			return errContinuityProtocolV4
		}
		s.mu.Lock()
		if command.ID != s.nextCommand+1 || command.ID > continuityCheckpointLimitV4+1 {
			s.mu.Unlock()
			return errContinuityProtocolV4
		}
		s.nextCommand = command.ID
		switch command.Operation {
		case "checkpoint":
			now, err := s.now()
			if s.role != "source" || !s.advertised || s.pending != nil || command.AfterBootNS <= 0 || err != nil || command.AfterBootNS > now {
				s.mu.Unlock()
				return errContinuityProtocolV4
			}
			s.pending = &nativeDHCPContinuityCheckpointV4{ID: command.ID, AfterBootNS: command.AfterBootNS}
			s.observeLocked()
			s.mu.Unlock()
		case "stop":
			if command.AfterBootNS != 0 || s.pending != nil {
				s.mu.Unlock()
				return errContinuityProtocolV4
			}
			s.mu.Unlock()
			if scan.Scan() || scan.Err() != nil || limited.N <= 0 {
				return errContinuityProtocolV4
			}
			s.mu.Lock()
			s.report.Stopped = true
			s.mu.Unlock()
			s.cancel()
			return nil
		default:
			s.mu.Unlock()
			return errContinuityProtocolV4
		}
	}
	return errors.Join(errors.New("continuity control EOF before explicit Stop"), scan.Err())
}
func continuityTerminationV4(stopped bool, ctxErr, prior error) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return errors.Join(errors.New("internal continuity budget exhausted"), prior)
	}
	if !stopped {
		return errors.Join(errors.New("continuity ended without explicit Stop"), prior)
	}
	return prior
}

// Child roles inherit FD3 target netns, FD4 parent netns, FD5 private reports.
// No parent namespace mutation and no host/public listener is permitted.
func TestNativeDHCPContinuityRoleV4(t *testing.T) {
	role := os.Getenv("ANDEIVA_CONTINUITY_ROLE_V4")
	if role == "" {
		t.Skip("isolated native child only")
	}
	if os.Getenv("ANDEIVA_NATIVE_DHCP_JOBS_V4") != "1" || os.Getenv("CI") != "" || os.Geteuid() != 0 || role != "source" && role != "sink" {
		t.Fatal("invalid native child")
	}
	profile, valid := continuityProfileFromEnvironmentV4(os.Getenv("ANDEIVA_CONTINUITY_PROFILE_V4"))
	if !valid {
		t.Fatal("invalid fixed native continuity profile")
	}
	pin, parentPin := os.NewFile(3, "target-netns"), os.NewFile(4, "parent-netns")
	defer pin.Close()
	defer parentPin.Close()
	info, err := pin.Stat()
	parentInfo, parentErr := parentPin.Stat()
	current, currentErr := os.Stat("/proc/self/ns/net")
	if err != nil || parentErr != nil || currentErr != nil || !os.SameFile(info, current) || os.SameFile(info, parentInfo) {
		t.Fatal("namespace pin mismatch")
	}
	for _, fd := range []int{0, 5} {
		if unix.SetNonblock(fd, true) != nil {
			t.Fatal("nonblocking private channel")
		}
	}
	input, output := os.NewFile(0, "private-control"), os.NewFile(5, "private-reports")
	defer input.Close()
	defer output.Close()
	var st unix.Stat_t
	if unix.Fstat(5, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		t.Fatal("private report descriptor is not a pipe")
	}
	window, _, _ := profile.limits()
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()
	s := &continuityStateV4{role: role, profile: profile, cancel: cancel, now: routedDHCPOwnerBootNowV3}
	s.emit = func(frame continuityFrameV4) error {
		if output.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			return errContinuityProtocolV4
		}
		return json.NewEncoder(output).Encode(frame)
	}
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		if err := readContinuityControlsV4(input, s); err != nil {
			s.mu.Lock()
			s.failLocked(err)
			s.mu.Unlock()
		}
	}()
	if role == "sink" {
		err = runContinuitySinkV4(ctx, s)
	} else {
		err = runContinuitySourceV4(ctx, s)
	}
	cancel()
	input.Close()
	<-controlDone
	r := s.snapshot()
	err = continuityTerminationV4(r.Stopped, ctx.Err(), errors.Join(err, s.failure))
	if err != nil {
		r.Error = err.Error()
		if len(r.Error) > 256 {
			r.Error = r.Error[:256]
		}
	}
	if e := s.emit(continuityFrameV4{Version: 1, Kind: "report", Report: &r}); e != nil {
		t.Error(e)
	}
	if err != nil {
		t.Fail()
	}
}
func runContinuitySinkV4(ctx context.Context, s *continuityStateV4) error {
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.18.1.1"), Port: 18080})
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.1.1"), Port: 18081})
	if err != nil {
		return err
	}
	defer udp.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			conn, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.report.TCPAccepted++
			first := s.report.TCPAccepted == 1
			if first {
				s.report.TCPSinkTuple = conn.RemoteAddr().String()
			} else {
				s.failLocked(errors.New("more than one TCP connection accepted"))
			}
			s.mu.Unlock()
			if !first {
				conn.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		defer wg.Done()
		var frame [9]byte
		for {
			n, peer, err := udp.ReadFromUDP(frame[:])
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.mu.Lock()
				transient := continuityTransientUDPV4(err)
				if transient {
					s.report.UDPSinkReadICMP++
				} else {
					s.failLocked(errors.New("sink UDP read failed"))
				}
				s.mu.Unlock()
				if !transient || !s.pause(ctx) {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			seq := binary.BigEndian.Uint64(frame[:8])
			s.mu.Lock()
			if n != 8 || seq == 0 || seq > continuityLimitV4 {
				s.report.UDPInvalid++
				s.failLocked(errors.New("invalid sink UDP datagram"))
				s.mu.Unlock()
				return
			}
			s.report.UDPSinkReceived++
			s.report.UDPSinkReceivedSet.add(seq)
			s.report.UDPSinkUniqueReceived = s.report.UDPSinkReceivedSet.count()
			if s.report.UDPSinkTuple == "" {
				s.report.UDPSinkTuple = peer.String()
			} else if s.report.UDPSinkTuple != peer.String() {
				s.report.UDPTupleChanges++
			}
			if s.report.UDPSinkReceived > continuityLimitV4*16 {
				s.failLocked(errors.New("sink UDP datagram bound exceeded"))
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			udp.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
			written, writeErr := udp.WriteToUDP(frame[:8], peer)
			s.mu.Lock()
			if writeErr == nil && written == 8 {
				s.report.UDPSinkEchoWrites++
				s.report.UDPSinkRepliedSet.add(seq)
				s.report.UDPSinkUniqueReplied = s.report.UDPSinkRepliedSet.count()
			} else {
				s.report.UDPReplyErrors++
				if written == 0 && continuityTransientUDPV4(writeErr) {
					s.report.UDPReplyICMP++
				} else if ctx.Err() == nil {
					s.failLocked(errors.New("sink UDP reply failed or was ambiguous"))
				}
			}
			s.mu.Unlock()
		}
	}()
	s.mu.Lock()
	s.observeLocked()
	s.mu.Unlock()
	<-ctx.Done()
	tcp.Close()
	udp.Close()
	wg.Wait()
	return nil
}
func runContinuitySourceV4(ctx context.Context, s *continuityStateV4) error {
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.18.0.2")}}
	tcp, err := dialer.DialContext(ctx, "tcp4", "198.18.1.1:18080")
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2")}, &net.UDPAddr{IP: net.ParseIP("198.18.1.1"), Port: 18081})
	if err != nil {
		return err
	}
	defer udp.Close()
	s.mu.Lock()
	s.report.TCPSource, s.report.TCPDestination = tcp.LocalAddr().String(), tcp.RemoteAddr().String()
	s.report.UDPSource, s.report.UDPDestination = udp.LocalAddr().String(), udp.RemoteAddr().String()
	s.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		s.sendUDP(ctx, func(frame []byte) (int, error) {
			if err := udp.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
				return 0, err
			}
			return udp.Write(frame)
		})
	}()
	go func() { defer wg.Done(); s.readUDP(ctx, udp.Read) }()
	go func() {
		defer wg.Done()
		var frame, echo [8]byte
		for seq := uint64(1); seq <= continuityLimitV4; seq++ {
			if !s.pause(ctx) {
				return
			}
			boot, err := s.now()
			if err != nil {
				s.mu.Lock()
				s.failLocked(err)
				s.mu.Unlock()
				return
			}
			binary.BigEndian.PutUint64(frame[:], seq)
			n, writeErr := tcp.Write(frame[:])
			s.mu.Lock()
			if writeErr == nil && n == 8 {
				s.report.TCPSent++
			} else if ctx.Err() == nil {
				s.report.TCPDisconnects++
				s.failLocked(errors.New("persistent TCP write failed"))
			}
			s.mu.Unlock()
			if writeErr != nil || n != 8 {
				return
			}
			_, readErr := io.ReadFull(tcp, echo[:])
			received, clockErr := s.now()
			s.mu.Lock()
			if readErr != nil || clockErr != nil || echo != frame || received < boot {
				if ctx.Err() == nil {
					s.report.TCPDisconnects++
					s.failLocked(errors.New("persistent TCP echo failed"))
				}
				s.mu.Unlock()
				return
			}
			s.report.TCPEchoed++
			if s.report.TCPFirstEchoBootNS == 0 {
				s.report.TCPFirstEchoBootNS = received
			}
			s.report.TCPLastEchoBootNS = received
			s.tcp = nativeDHCPContinuitySampleV4{seq, boot, received}
			s.observeLocked()
			s.mu.Unlock()
		}
		s.mu.Lock()
		s.failLocked(errors.New("TCP message bound exhausted"))
		s.mu.Unlock()
	}()
	<-ctx.Done()
	if raw, e := tcp.(*net.TCPConn).SyscallConn(); e == nil {
		_ = raw.Control(func(fd uintptr) {
			if info, e := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); e == nil {
				s.mu.Lock()
				s.report.TCPInfoAvailable, s.report.TCPTotalRetrans = true, info.Total_retrans
				s.mu.Unlock()
			}
		})
	}
	tcp.Close()
	time.Sleep(250 * time.Millisecond)
	udp.Close()
	wg.Wait()
	return nil
}

func continuityTestStateV4(role string) *continuityStateV4 {
	return &continuityStateV4{role: role, cancel: func() {}, now: func() (int64, error) { return 1000, nil }, emit: func(continuityFrameV4) error { return nil }}
}
func continuityTestReportV4() nativeDHCPContinuityReportV4 {
	r := nativeDHCPContinuityReportV4{Stopped: true, TCPSent: 1, TCPEchoed: 1, TCPFirstEchoBootNS: 100, TCPLastEchoBootNS: 100, TCPSource: "198.18.0.2:30000", TCPDestination: "198.18.1.1:18080", UDPSource: "198.18.0.2:30001", UDPDestination: "198.18.1.1:18081", UDPWriteAttempts: 1, UDPSent: 1, UDPUniqueEchoes: 1, FirstEchoBootNS: 100, LastEchoBootNS: 100}
	r.UDPSentSet.add(1)
	r.UDPSendStartBootNS[1], r.UDPSendEndBootNS[1] = 90, 91
	r.UDPEchoSet.add(1)
	return r
}

func TestDHCPContinuityFixedProfilesV4(t *testing.T) {
	for _, tc := range []struct {
		profile          continuityProfileV4
		window, interval time.Duration
	}{
		{continuityDefaultV4, 195 * time.Second, 25 * time.Millisecond},
		{continuityTenRenewalsV4, 650 * time.Second, 100 * time.Millisecond},
	} {
		window, interval, ok := tc.profile.limits()
		if !ok || window != tc.window || interval != tc.interval || window/interval > continuityLimitV4 {
			t.Fatal("fixed profile exceeds complete sequence coverage", tc.profile, window, interval)
		}
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			s := continuityTestStateV4("source")
			s.profile = tc.profile
			s.now = func() (int64, error) { return int64(100*time.Second + time.Since(start)), nil }
			writes := 0
			s.sendUDP(ctx, func(frame []byte) (int, error) {
				writes++
				if writes == 3 {
					cancel()
				}
				return len(frame), nil
			})
			if writes != 3 || time.Since(start) != 3*tc.interval || s.report.UDPSent != 3 || s.failure != nil {
				t.Fatal("probe rate or termination changed", writes, time.Since(start), s.failure)
			}
		})
	}
	for _, value := range []string{"", "0", "10"} {
		if _, ok := continuityProfileFromEnvironmentV4(value); !ok {
			t.Fatal("fixed child profile rejected", value)
		}
	}
	for _, value := range []string{"1", "650", "650s", "10s", "10 ", "-1"} {
		if _, ok := continuityProfileFromEnvironmentV4(value); ok {
			t.Fatal("arbitrary child profile accepted", value)
		}
	}
	if _, _, ok := continuityProfileV4(1).limits(); ok {
		t.Fatal("unknown typed profile accepted")
	}
}

func TestDHCPContinuityCollectorV4(t *testing.T) {
	s := continuityTestStateV4("source")
	s.echoLocked(1, 100)
	if s.failure == nil || s.report.UDPUniqueEchoes != 0 {
		t.Fatal("unsent echo reduced loss")
	}
	s = continuityTestStateV4("source")
	for seq := uint64(1); seq <= continuityLimitV4; seq++ {
		s.report.UDPSentSet.add(seq)
		s.sentAt[seq] = int64(seq) + 100
		s.sentEndAt[seq] = s.sentAt[seq]
	}
	s.report.UDPSent, s.report.UDPWriteAttempts = continuityLimitV4, continuityLimitV4
	s.echoLocked(1, 200)
	s.echoLocked(1, 201)
	r := s.snapshot()
	if r.UDPMissingEchoes != continuityLimitV4-1 || len(r.Missing) != continuityLimitV4-1 || r.MissingTruncated || r.UDPDuplicates != 1 {
		t.Fatal("incomplete loss accounting")
	}
	encoded, err := json.Marshal(continuityFrameV4{Version: 1, Kind: "report", Report: &r})
	if err != nil || len(encoded) > continuityJSONLimitV4 {
		t.Fatal("full loss window exceeds report limit")
	}
	r = continuityTestReportV4()
	r.UDPSinkReceivedSet.add(1)
	r.UDPSinkRepliedSet.add(1)
	r.UDPSinkUniqueReceived, r.UDPSinkUniqueReplied = 1, 1
	if continuityDirectionsV4(&r) != nil || r.UDPRequestMissing != 0 || r.UDPReplyMissing != 0 {
		t.Fatal("directional reconciliation failed")
	}
	r.UDPSinkReceivedSet.add(2)
	if continuityDirectionsV4(&r) == nil {
		t.Fatal("sink invented a request")
	}
	r = continuityTestReportV4()
	r.UDPSent, r.UDPWriteAttempts, r.UDPMissingEchoes = 4, 4, 3
	for seq := uint64(2); seq <= 4; seq++ {
		r.UDPSentSet.add(seq)
	}
	for _, seq := range []uint64{1, 3, 4} {
		r.UDPSinkReceivedSet.add(seq)
	}
	for _, seq := range []uint64{1, 3} {
		r.UDPSinkRepliedSet.add(seq)
	}
	r.UDPSinkUniqueReceived, r.UDPSinkUniqueReplied = 3, 2
	if continuityDirectionsV4(&r) != nil || r.UDPRequestMissing != 1 || r.UDPReplyMissing != 1 || r.UDPSinkUnanswered != 1 {
		t.Fatal("nonzero losses were rejected or attributed to the wrong direction")
	}
	s = continuityTestStateV4("source")
	for seq := uint64(1); seq <= continuityLimitV4; seq++ {
		s.report.UDPSentSet.add(seq)
		s.sentAt[seq] = int64(1<<62) + int64(seq)
		s.sentEndAt[seq] = s.sentAt[seq]
	}
	s.report.UDPSent, s.report.UDPWriteAttempts = continuityLimitV4, continuityLimitV4
	r = s.snapshot()
	encoded, err = json.Marshal(continuityFrameV4{Version: 1, Kind: "report", Report: &r})
	if err != nil || len(r.Missing) != continuityLimitV4 || len(encoded) > continuityJSONLimitV4 {
		t.Fatal("entire missing-probe window is not bounded and complete")
	}
	t.Logf("full8192 UDP writes+missing+both timestamp arrays encoded bytes=%d limit=%d", len(encoded), continuityJSONLimitV4)
}
func TestDHCPContinuityPrivateProtocolV4(t *testing.T) {
	ready := []byte(`{"version":1,"kind":"ready"}`)
	for _, bad := range []string{`{"version":1,"version":1,"kind":"ready"}`, `{"version":1,"kind":"ready","extra":true}`, `{"Version":1,"kind":"ready"}`, `{"version":1,"kind":"ready"} {}`, `{"version":1,"kind":"ready","report":null}`} {
		p := continuityProtocolV4{role: "source"}
		if _, err := p.accept([]byte(bad)); err == nil {
			t.Fatal("nonexact frame accepted", bad)
		}
	}
	r := continuityTestReportV4()
	report, _ := json.Marshal(continuityFrameV4{Version: 1, Kind: "report", Report: &r})
	for _, bad := range []string{string(ready) + "\n" + string(ready) + "\n" + string(report) + "\n", string(ready) + "\n" + string(report) + "\n{}\n", string(ready) + "\n" + string(report) + "\n ", string(report) + "\n"} {
		p := continuityProtocolV4{role: "source", stopRequested: true}
		if err := readContinuityFramesV4(bytes.NewBufferString(bad), func(raw []byte) error { _, err := p.accept(raw); return err }); err == nil {
			t.Fatal("invalid stream accepted")
		}
	}
	p := continuityProtocolV4{role: "source", stopRequested: true}
	if err := readContinuityFramesV4(bytes.NewBufferString(string(ready)+"\n"+string(report)+"\n"), func(raw []byte) error { _, err := p.accept(raw); return err }); err != nil || !p.final {
		t.Fatal("valid exact EOF rejected", err)
	}
	r.UDPEchoSet.add(2)
	if continuityReportValidV4("source", r) {
		t.Fatal("inconsistent report accepted")
	}
	r = continuityTestReportV4()
	encoded, _ := json.Marshal(r)
	var fields map[string]json.RawMessage
	json.Unmarshal(encoded, &fields)
	delete(fields, "udp_send_errors")
	encoded, _ = json.Marshal(fields)
	var decoded nativeDHCPContinuityReportV4
	if continuityDecodeV4(encoded, &decoded) == nil {
		t.Fatal("missing zero field accepted")
	}
	r = continuityTestReportV4()
	encoded, _ = json.Marshal(r)
	json.Unmarshal(encoded, &fields)
	fields["udp_sent_set"] = json.RawMessage(`[1]`)
	encoded, _ = json.Marshal(fields)
	if continuityDecodeV4(encoded, &decoded) == nil {
		t.Fatal("short fixed bitmap accepted")
	}
	r = continuityTestReportV4()
	r.UDPSendErrors = ^uint64(0)
	if continuityReportValidV4("source", r) {
		t.Fatal("overflowing accounting accepted")
	}
	if readContinuityFramesV4(bytes.NewReader(bytes.Repeat([]byte("x"), continuityJSONLimitV4+2)), func([]byte) error { return nil }) == nil {
		t.Fatal("oversized private channel accepted")
	}
}

func TestDHCPContinuityIdempotentStopV4(t *testing.T) {
	cancels := 0
	child := func(r nativeDHCPContinuityReportV4) *continuityChildV4 {
		readEnd, writeEnd := io.Pipe()
		t.Cleanup(func() { readEnd.Close(); writeEnd.Close() })
		done := make(chan struct{})
		close(done)
		return &continuityChildV4{input: writeEnd, cancel: func() { cancels++ }, done: done, result: r}
	}
	sink := nativeDHCPContinuityReportV4{Stopped: true, TCPAccepted: 1, TCPSinkTuple: "198.18.1.10:30000", UDPSinkTuple: "198.18.1.10:30001", UDPSinkReceived: 1, UDPSinkUniqueReceived: 1, UDPSinkEchoWrites: 1, UDPSinkUniqueReplied: 1}
	sink.UDPSinkReceivedSet.add(1)
	sink.UDPSinkRepliedSet.add(1)
	h := &nativeDHCPContinuityV4{source: child(continuityTestReportV4()), sink: child(sink)}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := h.Stop()
			if err != nil || r.TCPAccepted != 1 || r.UDPSinkUniqueReceived != 1 {
				t.Error("idempotent stop changed the result", err)
			}
		})
	}
	wg.Wait()
	if cancels != 2 {
		t.Fatal("stop cleaned each child more than once")
	}
}
func TestDHCPContinuityStopEOFAndDeadlineV4(t *testing.T) {
	for _, bad := range []string{"", `{"version":1,"operation":"stop","id":1,"after_boot_ns":0}` + "\n{}\n"} {
		s := continuityTestStateV4("source")
		if readContinuityControlsV4(bytes.NewBufferString(bad), s) == nil || s.report.Stopped {
			t.Fatal("EOF/trailing input became normal Stop")
		}
	}
	s := continuityTestStateV4("source")
	if err := readContinuityControlsV4(bytes.NewBufferString(`{"version":1,"operation":"stop","id":1,"after_boot_ns":0}`+"\n"), s); err != nil || !s.report.Stopped {
		t.Fatal("explicit stop failed", err)
	}
	if continuityTerminationV4(true, context.Canceled, nil) != nil || continuityTerminationV4(false, context.Canceled, nil) == nil || continuityTerminationV4(true, context.DeadlineExceeded, nil) == nil {
		t.Fatal("deadline/EOF accepted as successful stop")
	}
}
func TestDHCPContinuityICMPKeepsFlowV4(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := continuityTestStateV4("source")
		calls := 0
		s.sendUDP(ctx, func(frame []byte) (int, error) {
			calls++
			if calls == 1 {
				return 0, &net.OpError{Op: "write", Err: syscall.ECONNREFUSED}
			}
			cancel()
			return len(frame), nil
		})
		if calls != 2 || s.failure != nil || s.report.UDPWriteAttempts != 2 || s.report.UDPSent != 1 || s.report.UDPSendErrors != 1 || s.report.UDPWriteICMP != 1 || s.report.UDPSentSet.has(1) || !s.report.UDPSentSet.has(2) {
			t.Fatal("ICMP write killed flow or counted failed attempt as sent")
		}
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
		calls = 0
		s.readUDP(ctx, func(frame []byte) (int, error) {
			calls++
			if calls == 1 {
				return 0, syscall.EHOSTUNREACH
			}
			if calls == 2 {
				binary.BigEndian.PutUint64(frame, 2)
				return 8, nil
			}
			cancel()
			return 0, net.ErrClosed
		})
		if calls != 3 || s.failure != nil || s.report.UDPReadICMP != 1 || s.report.UDPUniqueEchoes != 1 {
			t.Fatal("ICMP read killed persistent flow")
		}
	})
	for _, fatal := range []error{syscall.EBADF, net.ErrClosed, io.EOF} {
		if continuityTransientUDPV4(fatal) {
			t.Fatal("permanent socket failure treated as ICMP")
		}
	}
}
func TestDHCPContinuityCheckpointRequiresNewSendsV4(t *testing.T) {
	s := continuityTestStateV4("source")
	s.advertised = true
	var acks []nativeDHCPContinuityCheckpointV4
	s.emit = func(f continuityFrameV4) error {
		if f.Checkpoint != nil {
			acks = append(acks, *f.Checkpoint)
		}
		return nil
	}
	s.pending = &nativeDHCPContinuityCheckpointV4{ID: 1, AfterBootNS: 100}
	s.tcp = nativeDHCPContinuitySampleV4{1, 99, 110}
	s.udp = nativeDHCPContinuitySampleV4{2, 101, 111}
	s.observeLocked()
	if len(acks) != 0 {
		t.Fatal("late echo of old send proved post-reopen traffic")
	}
	s.tcp = nativeDHCPContinuitySampleV4{2, 102, 112}
	s.observeLocked()
	s.observeLocked()
	if len(acks) != 1 || !continuityCheckpointValidV4(acks[0]) || s.pending != nil {
		t.Fatal("checkpoint did not acknowledge fresh bidirectional echoes exactly once")
	}
}
