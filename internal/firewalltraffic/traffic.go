// Package firewalltraffic retains bounded, on-request rule counter observations.
// Records describe sampling intervals, never individual packets or connections.
package firewalltraffic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const Capacity = 512

var (
	ErrInvalid       = errors.New("ANDEIVA_TRAFFIC_INVALID")
	ErrUnavailable   = errors.New("ANDEIVA_TRAFFIC_UNAVAILABLE")
	ErrStreamChanged = errors.New("ANDEIVA_TRAFFIC_STREAM_CHANGED")
)

type Counter struct {
	ID      string `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
type Observation struct {
	Revision     configpoc.Revision
	CounterEpoch string
	Counters     []Counter
}
type Record struct {
	Sequence     uint64     `json:"sequence"`
	ObservedAt   time.Time  `json:"observed_at"`
	Since        *time.Time `json:"since,omitempty"`
	Revision     string     `json:"revision"`
	RuleID       string     `json:"rule_id"`
	Action       string     `json:"action"`
	Kind         string     `json:"kind"`
	PacketsTotal string     `json:"packets_total"`
	BytesTotal   string     `json:"bytes_total"`
	PacketsDelta string     `json:"packets_delta,omitempty"`
	BytesDelta   string     `json:"bytes_delta,omitempty"`
}
type Page struct {
	Stream     string   `json:"stream"`
	Records    []Record `json:"records"`
	NextBefore uint64   `json:"next_before"`
	Evicted    uint64   `json:"evicted"`
	Capacity   int      `json:"capacity"`
	Sampling   string   `json:"sampling"`
	Retention  string   `json:"retention"`
	Truncated  bool     `json:"truncated"`
}
type Sampler struct {
	gate              chan struct{}
	stream            string
	ring              [Capacity]Record
	next, size        int
	sequence, evicted uint64
	base              map[string]Counter
	revision, epoch   string
	observed          time.Time
	now               func() time.Time
}

func New() (*Sampler, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, ErrUnavailable
	}
	return &Sampler{gate: make(chan struct{}, 1), stream: hex.EncodeToString(id[:]), now: time.Now}, nil
}

// Read serializes the entire sample and insertion, with context-bounded waiting.
// Historical pages never invoke sample or alter the counter baseline.
func (s *Sampler) Read(ctx context.Context, before uint64, limit int, stream string, sample func(context.Context) (Observation, error)) (Page, error) {
	if limit < 1 || limit > 100 || (before == 0 && stream != "") || (before > 0 && stream == "") || sample == nil {
		return Page{}, ErrInvalid
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return Page{}, ErrUnavailable
	}
	defer func() { <-s.gate }()
	if ctx.Err() != nil {
		return Page{}, ErrUnavailable
	}
	if before > 0 && stream != s.stream {
		return Page{}, ErrStreamChanged
	}
	if before == 0 {
		observation, err := sample(ctx)
		if err != nil || ctx.Err() != nil {
			s.invalidate()
			return Page{}, ErrUnavailable
		}
		if err = s.record(observation); err != nil {
			s.invalidate()
			return Page{}, err
		}
	}
	page := Page{Stream: s.stream, Records: []Record{}, Evicted: s.evicted, Capacity: Capacity, Sampling: "on_request", Retention: "api_process"}
	if before > 0 && s.evicted > 0 && s.size > 0 {
		oldest := s.ring[(s.next-s.size+Capacity)%Capacity].Sequence
		page.Truncated = before <= oldest
	}
	for i := 0; i < s.size; i++ {
		record := s.ring[(s.next-1-i+Capacity)%Capacity]
		if before > 0 && record.Sequence >= before {
			continue
		}
		if len(page.Records) == limit {
			page.NextBefore = page.Records[len(page.Records)-1].Sequence
			break
		}
		if record.Since != nil {
			since := *record.Since
			record.Since = &since
		}
		page.Records = append(page.Records, record)
	}
	if s.evicted > 0 && len(page.Records) > 0 {
		oldest := s.ring[(s.next-s.size+Capacity)%Capacity].Sequence
		if page.Records[len(page.Records)-1].Sequence == oldest {
			page.Truncated = true
		}
	}
	return page, nil
}
func (s *Sampler) invalidate() { s.base = nil; s.revision = ""; s.epoch = ""; s.observed = time.Time{} }
func (s *Sampler) record(observation Observation) error {
	revision, err := configpoc.Canonical(observation.Revision.Config)
	active := 0
	for _, rule := range revision.Config.Rules {
		if rule.IsEnabled() {
			active++
		}
	}
	if err != nil || revision.Hash != observation.Revision.Hash || (revision.Config.SchemaVersion != 2 && revision.Config.SchemaVersion != 4) || len(observation.CounterEpoch) == 0 || len(observation.CounterEpoch) > 128 || len(observation.Counters) != active {
		return ErrUnavailable
	}
	counters := make(map[string]Counter, len(observation.Counters))
	for _, counter := range observation.Counters {
		if _, exists := counters[counter.ID]; exists {
			return ErrUnavailable
		}
		counters[counter.ID] = counter
	}
	for _, rule := range revision.Config.Rules {
		if !rule.IsEnabled() {
			continue
		}
		if _, ok := counters[rule.ID]; !ok {
			return ErrUnavailable
		}
	}
	now := s.now().UTC()
	if !s.observed.IsZero() && now.Before(s.observed) {
		return ErrUnavailable
	}
	baseline := s.base == nil || s.revision != revision.Hash || s.epoch != observation.CounterEpoch
	if !baseline {
		for id, counter := range counters {
			previous, ok := s.base[id]
			if !ok || counter.Packets < previous.Packets || counter.Bytes < previous.Bytes {
				return ErrUnavailable
			}
		}
	}
	if s.sequence > ^uint64(0)-uint64(len(counters)) {
		return ErrUnavailable
	}
	for _, rule := range revision.Config.Rules {
		if !rule.IsEnabled() {
			continue
		}
		counter := counters[rule.ID]
		record := Record{ObservedAt: now, Revision: revision.Hash, RuleID: rule.ID, Action: rule.Action, Kind: "baseline", PacketsTotal: strconv.FormatUint(counter.Packets, 10), BytesTotal: strconv.FormatUint(counter.Bytes, 10)}
		if !baseline {
			previous := s.base[rule.ID]
			packets, bytes := counter.Packets-previous.Packets, counter.Bytes-previous.Bytes
			if packets == 0 && bytes == 0 {
				continue
			}
			since := s.observed
			record.Since = &since
			record.Kind = "delta"
			record.PacketsDelta = strconv.FormatUint(packets, 10)
			record.BytesDelta = strconv.FormatUint(bytes, 10)
		}
		s.sequence++
		record.Sequence = s.sequence
		s.ring[s.next] = record
		s.next = (s.next + 1) % Capacity
		if s.size < Capacity {
			s.size++
		} else {
			s.evicted++
		}
	}
	s.base = counters
	s.revision = revision.Hash
	s.epoch = observation.CounterEpoch
	s.observed = now
	return nil
}
