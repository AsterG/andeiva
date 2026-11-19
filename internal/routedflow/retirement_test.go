package routedflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

func retirementFixture(t *testing.T) (*Retirement, Flow, Flow) {
	t.Helper()
	policy := routednft.LabPolicy()
	before, err := routedmodel.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Rules[0].Action = "deny"
	target, err := routedmodel.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRetirement("fixture.commit", 11, 12, before, target)
	if err != nil {
		t.Fatal(err)
	}
	affected := retirementFlow(before.Policy.Rules[0], 1)
	retained := retirementFlow(before.Policy.Rules[1], 2)
	return plan, affected, retained
}

func retirementFlow(rule routedmodel.Rule, id uint32) Flow {
	mark := routedmodel.RuleMark(rule)
	return Flow{
		ID: &id, Mark: &mark,
		Original: Tuple{Source: Endpoint{Address: netip.MustParseAddr("198.18.0.2"), Port: 45678},
			Destination: Endpoint{Address: netip.MustParseAddr("198.19.0.2"), Port: rule.DestinationPorts.From},
			Protocol:    rule.Protocol},
	}
}

func TestRetirementSelectsOnlyAffectedEntries(t *testing.T) {
	plan, affected, retained := retirementFixture(t)
	foreign := retained
	unowned := uint32(0x12345678)
	foreign.Mark = &unowned
	got, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{retained, foreign, affected}})
	if err != nil || len(got) != 1 || got[0].id != *affected.ID || got[0].original != affected.Original {
		t.Fatal("retirement selected the wrong entries", err)
	}
	unknown := uint32(0xadffffff)
	affected.Mark = &unknown
	if got, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{affected}}); !errors.Is(err, ErrObservation) || len(got) != 0 {
		t.Fatal("unproven historical mark did not fail closed", err)
	}
}

func TestRetirementRejectsOverBudgetBeforeDeleting(t *testing.T) {
	plan, affected, _ := retirementFixture(t)
	snapshot := Snapshot{SchemaVersion: 1}
	for i := 0; i <= MaxRetirements; i++ {
		entry := affected
		entry.Original.Source.Port += uint16(i)
		snapshot.Flows = append(snapshot.Flows, entry)
	}
	if got, err := plan.selectAffected(snapshot); !errors.Is(err, ErrLimit) || len(got) != 0 {
		t.Fatal("over-budget retirement returned a partial list", err)
	}
}

func TestRetirementUsesFirstMatchingRuleInBothPolicies(t *testing.T) {
	policy := routednft.LabPolicy()
	before, err := routedmodel.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	deny := before.Policy.Rules[0]
	deny.ID, deny.Action = "deny-before-allow", "deny"
	policy.Rules = append([]routedmodel.Rule{deny}, policy.Rules...)
	target, err := routedmodel.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRetirement("fixture.commit", 11, 12, before, target)
	if err != nil {
		t.Fatal(err)
	}
	affected := retirementFlow(before.Policy.Rules[0], 1)
	retained := retirementFlow(before.Policy.Rules[1], 2)
	got, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{affected, retained}})
	if err != nil || len(got) != 1 || got[0].id != *affected.ID {
		t.Fatal("an existing rule retained a connection denied by an earlier rule", err)
	}
}

func TestRetirementRequestRequiresPointIdentity(t *testing.T) {
	plan, affected, _ := retirementFixture(t)
	got, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{affected}})
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	entry := got[0]
	for _, protocol := range []struct {
		name   string
		number byte
	}{{"tcp", 6}, {"udp", 17}} {
		entry.original.Protocol = protocol.name
		raw, err := retireRequest(testSeq, testPort, entry)
		data := join([]byte{2, 0, 0, 0},
			tuple(1, "198.18.0.2", "198.19.0.2", 45678, 18080, protocol.number),
			attr(12, be32(1)), attr(18, be16(0)))
		if err != nil || !bytes.Equal(raw, message(ctDelete, 5, data)) {
			t.Fatal("request was not an exact tuple/ID/zone deletion", protocol.name, err)
		}
	}
	entry.id = 0
	if raw, err := retireRequest(testSeq, testPort, entry); !errors.Is(err, ErrObservation) || raw != nil {
		t.Fatal("delete request allowed a missing identity", err)
	}
}

func TestRetirementRequiresExactKernelAcknowledgement(t *testing.T) {
	plan, affected, _ := retirementFixture(t)
	keys, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{affected}})
	if err != nil || len(keys) != 1 {
		t.Fatal(err)
	}
	request, err := retireRequest(testSeq, testPort, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	ack := message(2, 0x100, join(make([]byte, 4), request[:16]))
	for _, tc := range []struct {
		name    string
		change  func(*datagram)
		wantErr bool
	}{
		{name: "exact"},
		{name: "foreign peer", change: func(d *datagram) { d.peerPort++ }, wantErr: true},
		{name: "truncated", change: func(d *datagram) { d.truncated = true }, wantErr: true},
		{name: "wrong sequence", change: func(d *datagram) { binary.NativeEndian.PutUint32(d.data[8:], testSeq+1) }, wantErr: true},
		{name: "wrong quote", change: func(d *datagram) { d.data[24] ^= 1 }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := datagram{data: bytes.Clone(ack)}
			if tc.change != nil {
				tc.change(&d)
			}
			f := &fakeTransport{packets: []datagram{d}}
			if err := retireEntry(context.Background(), f, testSeq, testPort, keys[0]); (err != nil) != tc.wantErr {
				t.Fatal("unexpected acknowledgement outcome", err)
			}
		})
	}
}

func retirementDumpFlow(f Flow, sequence uint32) datagram {
	protocol := byte(6)
	if f.Original.Protocol == "udp" {
		protocol = 17
	}
	src, dst := f.Original.Source, f.Original.Destination
	data := join([]byte{2, 0, 0, 0},
		tuple(1, src.Address.String(), dst.Address.String(), src.Port, dst.Port, protocol),
		tuple(2, dst.Address.String(), src.Address.String(), dst.Port, src.Port, protocol),
		attr(8, be32(*f.Mark)), attr(12, be32(*f.ID)))
	msg := message(ctNew, flagMulti, data)
	binary.NativeEndian.PutUint32(msg[8:], sequence)
	return datagram{data: msg}
}

func TestRetirementChecksTheCompleteDumpBeforeAndAfterPointDeletion(t *testing.T) {
	plan, affected, retained := retirementFixture(t)
	for _, tc := range []struct {
		name       string
		initial    int
		stillThere bool
		want       error
		sent       int
	}{
		{name: "only affected retired", initial: 1, sent: 3},
		{name: "remaining entry requires recovery", initial: 1, stillThere: true, want: ErrObservation, sent: 3},
		{name: "limit prevents mutation", initial: MaxRetirements + 1, want: ErrLimit, sent: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTransport{}
			for i := 0; i < tc.initial; i++ {
				flow := affected
				flow.Original.Source.Port += uint16(i)
				id := uint32(i + 1)
				flow.ID = &id
				f.packets = append(f.packets, retirementDumpFlow(flow, testSeq))
			}
			f.packets = append(f.packets, retirementDumpFlow(retained, testSeq), datagram{data: done()})
			if tc.sent > 1 {
				keys, err := plan.selectAffected(Snapshot{SchemaVersion: 1, Flows: []Flow{affected}})
				if err != nil || len(keys) != 1 {
					t.Fatal("fixture selection", err)
				}
				req, err := retireRequest(testSeq+1, testPort, keys[0])
				if err != nil {
					t.Fatal(err)
				}
				ack := message(2, 0x100, join(make([]byte, 4), req[:16]))
				binary.NativeEndian.PutUint32(ack[8:], testSeq+1)
				f.packets = append(f.packets, datagram{data: ack}, retirementDumpFlow(retained, testSeq+2))
				if tc.stillThere {
					f.packets = append(f.packets, retirementDumpFlow(affected, testSeq+2))
				}
				end := done()
				binary.NativeEndian.PutUint32(end[8:], testSeq+2)
				f.packets = append(f.packets, datagram{data: end})
			}
			result, err := plan.run(context.Background(), f, testSeq, testPort)
			if !errors.Is(err, tc.want) || len(f.sent) != tc.sent || result.Operation != plan.operation {
				t.Fatalf("result=%+v error=%v messages=%d", result, err, len(f.sent))
			}
			if tc.sent > 1 && (result.Retired != 1 || binary.NativeEndian.Uint16(f.sent[1][4:]) != ctDelete) {
				t.Fatal("expected one acknowledged point deletion between the dumps")
			}
		})
	}
}
