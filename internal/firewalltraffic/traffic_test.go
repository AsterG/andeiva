package firewalltraffic

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func sampleFixture(t *testing.T) (*Sampler, Observation) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	config := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "web", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}}
	revision, err := configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	return s, Observation{Revision: revision, CounterEpoch: strings.Repeat("a", 32) + ".1", Counters: []Counter{{ID: "web", Packets: 5, Bytes: 300}}}
}
func readSample(t *testing.T, s *Sampler, o Observation) Page {
	t.Helper()
	p, err := s.Read(context.Background(), 0, 100, "", func(context.Context) (Observation, error) { return o, nil })
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestBaselineDeltaAndNoInventedZero(t *testing.T) {
	s, o := sampleFixture(t)
	clock := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	p := readSample(t, s, o)
	if len(p.Records) != 1 || p.Records[0].Kind != "baseline" || p.Records[0].PacketsTotal != "5" || p.Records[0].Since != nil || p.Records[0].PacketsDelta != "" {
		t.Fatal(p)
	}
	clock = clock.Add(time.Second)
	p = readSample(t, s, o)
	if len(p.Records) != 1 {
		t.Fatal("invented zero event")
	}
	o.Counters[0].Packets += 2
	o.Counters[0].Bytes += 100
	clock = clock.Add(time.Second)
	p = readSample(t, s, o)
	r := p.Records[0]
	if r.Kind != "delta" || r.PacketsDelta != "2" || r.BytesDelta != "100" || r.Action != "allow" || r.Since == nil || !r.Since.Equal(clock.Add(-time.Second)) {
		t.Fatal(r)
	}
	// A caller cannot mutate retained timestamps through a returned page.
	*r.Since = time.Time{}
	p = readSample(t, s, o)
	if p.Records[0].Since.IsZero() {
		t.Fatal("page aliases retained record")
	}
}
func TestEpochRevisionAndProcessBaselines(t *testing.T) {
	s, o := sampleFixture(t)
	first := readSample(t, s, o)
	o.CounterEpoch = strings.Repeat("a", 32) + ".2"
	o.Counters[0].Packets = 1
	o.Counters[0].Bytes = 60
	p := readSample(t, s, o)
	if p.Records[0].Kind != "baseline" || p.Records[0].PacketsDelta != "" {
		t.Fatal("same revision reset fabricated delta")
	}
	o.Revision.Config.Rules[0].Action = "deny"
	o.Revision, _ = configpoc.Canonical(o.Revision.Config)
	p = readSample(t, s, o)
	if p.Records[0].Kind != "baseline" || p.Records[0].Action != "deny" {
		t.Fatal("revision action not rebound")
	}
	restarted, err := New()
	if err != nil {
		t.Fatal(err)
	}
	p = readSample(t, restarted, o)
	if p.Stream == first.Stream || p.Records[0].Sequence != 1 || p.Records[0].Kind != "baseline" {
		t.Fatal("process retention not reset")
	}
}
func TestInvalidSamplesNeverAdvanceRecords(t *testing.T) {
	for _, kind := range []string{"decrease", "bytes-decrease", "missing", "duplicate", "extra", "hash", "epoch", "clock", "unavailable", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			s, o := sampleFixture(t)
			clock := time.Now()
			s.now = func() time.Time { return clock }
			readSample(t, s, o)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var sampleErr error
			switch kind {
			case "decrease":
				o.Counters[0].Packets--
			case "bytes-decrease":
				o.Counters[0].Bytes--
			case "missing":
				o.Counters = nil
			case "duplicate":
				o.Counters = append(o.Counters, o.Counters[0])
			case "extra":
				o.Counters[0].ID = "untrusted"
			case "hash":
				o.Revision.Hash = strings.Repeat("f", 64)
			case "epoch":
				o.CounterEpoch = ""
			case "clock":
				clock = clock.Add(-time.Second)
			case "unavailable":
				sampleErr = errors.New("private")
			}
			_, err := s.Read(ctx, 0, 10, "", func(context.Context) (Observation, error) {
				if kind == "canceled" {
					cancel()
				}
				return o, sampleErr
			})
			if !errors.Is(err, ErrUnavailable) || s.sequence != 1 || s.base != nil {
				t.Fatal("invalid sample retained", err, s.sequence)
			}
			_, valid := sampleFixture(t)
			p := readSample(t, s, valid)
			if p.Records[0].Kind != "baseline" {
				t.Fatal("invalidated baseline reused")
			}
		})
	}
}
func TestStablePagesEvictionAndStreamBinding(t *testing.T) {
	s, o := sampleFixture(t)
	for i := 0; i < Capacity+4; i++ {
		o.Counters[0].Packets++
		o.Counters[0].Bytes += 60
		readSample(t, s, o)
	}
	failSample := func(context.Context) (Observation, error) { t.Fatal("older page sampled"); return Observation{}, nil }
	p, err := s.Read(context.Background(), 513, 2, s.stream, failSample)
	if err != nil || len(p.Records) != 2 || p.Records[0].Sequence != 512 || p.Records[1].Sequence != 511 || p.NextBefore != 511 || p.Evicted != 4 || p.Capacity != 512 || p.Retention != "api_process" || p.Sampling != "on_request" {
		t.Fatal(p, err)
	}
	o.Counters[0].Packets++
	readSample(t, s, o)
	next, err := s.Read(context.Background(), p.NextBefore, 2, s.stream, failSample)
	if err != nil || next.Records[0].Sequence != 510 {
		t.Fatal("cursor unstable", next, err)
	}
	p, err = s.Read(context.Background(), 5, 10, s.stream, failSample)
	if err != nil || !p.Truncated || len(p.Records) != 0 {
		t.Fatal("evicted cursor not explicit", p, err)
	}
	p, err = s.Read(context.Background(), 10, 10, s.stream, failSample)
	if err != nil || !p.Truncated || p.NextBefore != 0 || len(p.Records) != 4 || p.Records[0].Sequence != 9 || p.Records[3].Sequence != 6 {
		t.Fatal("partially retained final page hid lost history", p, err)
	}
	if _, err = s.Read(context.Background(), 3, 10, strings.Repeat("b", 32), failSample); !errors.Is(err, ErrStreamChanged) {
		t.Fatal("cross-stream cursor accepted")
	}
	for _, test := range []struct {
		before uint64
		limit  int
		stream string
	}{{0, 0, ""}, {0, 101, ""}, {1, 1, ""}, {0, 1, s.stream}} {
		if _, err = s.Read(context.Background(), test.before, test.limit, test.stream, failSample); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad page accepted")
		}
	}
}
func TestLargeCountersAreDecimalStrings(t *testing.T) {
	s, o := sampleFixture(t)
	o.Counters[0].Packets = ^uint64(0) - 1
	o.Counters[0].Bytes = ^uint64(0) - 2
	readSample(t, s, o)
	o.Counters[0].Packets++
	o.Counters[0].Bytes += 2
	p := readSample(t, s, o)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"packets_total":"18446744073709551615"`) || p.Records[0].PacketsDelta != "1" || p.Records[0].BytesDelta != "2" {
		t.Fatal(string(data))
	}
}
func TestSerializedSamplingAndCanceledWait(t *testing.T) {
	s, o := sampleFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(context.Background(), 0, 10, "", func(context.Context) (Observation, error) { close(entered); <-release; return o, nil })
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Read(ctx, 0, 10, "", func(context.Context) (Observation, error) { t.Error("canceled waiter sampled"); return o, nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Read(context.Background(), 0, 10, "", func(context.Context) (Observation, error) { return o, nil }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if s.sequence != 1 {
		t.Fatal("concurrency fabricated events")
	}
}
