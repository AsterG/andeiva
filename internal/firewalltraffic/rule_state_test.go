package firewalltraffic

import (
	"github.com/AsterG/andeiva/internal/configpoc"
	"testing"
)

func TestInactiveRulesHaveNoSyntheticCountersOrDeltas(t *testing.T) {
	s, o := sampleFixture(t)
	readSample(t, s, o)
	c := o.Revision.Config
	c.SchemaVersion = 4
	enabled := false
	c.Rules[0].Enabled = &enabled
	o.Revision, _ = configpoc.Canonical(c)
	o.Counters = nil
	p := readSample(t, s, o)
	if len(p.Records) != 1 {
		t.Fatal("inactive rule invented traffic")
	}
	bad := o
	bad.Counters = []Counter{{ID: "web"}}
	if err := s.record(bad); err == nil {
		t.Fatal("counter for inactive rule accepted")
	}
	enabled = true
	o.Revision, _ = configpoc.Canonical(c)
	o.Counters = []Counter{{ID: "web", Packets: 1, Bytes: 40}}
	p = readSample(t, s, o)
	if len(p.Records) != 2 || p.Records[0].Kind != "baseline" || p.Records[0].PacketsDelta != "" {
		t.Fatal("reenabled rule fabricated a delta")
	}
}
