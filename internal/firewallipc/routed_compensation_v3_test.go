package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedCompensationV3UsesExistingProtocol(t *testing.T) {
	run, work := strings.Repeat("a", 32), strings.Repeat("b", 64)
	digest, ticket := strings.Repeat("c", 64), strings.Repeat("d", 64)
	ref := RoutedReferenceV3{Work: work, Lineage: "fixture", Generation: "2"}
	request := RoutedRequestV3{ProtocolVersion: RoutedProtocolV3, Run: run, Sequence: 1, Namespace: 4, Domain: "routed"}
	selection := configpoc.SelectionReferenceV2{Selection: digest, State: digest, Lineage: ref.Lineage, Sequence: 3, Generation: 1, WorkHash: work, Mode: "intent"}
	compensation := RoutedCompensationV3{Reference: ref, Selection: selection, Operation: "operation"}

	encode := func(v any) []byte {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	request.Verb, request.Payload = "prepare_recover", encode(compensation)
	_, cmd, err := DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0)
	if err != nil || cmd.Compensation == nil || *cmd.Compensation != compensation {
		t.Fatal("prepare request rejected", err)
	}
	reply := RoutedReplyV3{ProtocolVersion: RoutedProtocolV3, Run: run, Sequence: 1, Namespace: 4, Domain: "routed", Verb: request.Verb, Payload: encode(RoutedCompensationPreparedV3{Ticket: ticket})}
	_, result, err := DecodeRoutedReplyV3(encode(reply), request)
	if err != nil || result.Compensation.Ticket != ticket {
		t.Fatal("prepare reply rejected", err)
	}
	reply.Payload = json.RawMessage(`{"ticket":null}`)
	if _, _, err := DecodeRoutedReplyV3(encode(reply), request); err == nil {
		t.Fatal("accepted a null ticket")
	}
	compensation.Ticket = ticket
	request.Verb, request.Payload = "recover", encode(compensation)
	_, cmd, err = DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0)
	if err != nil || cmd.Compensation == nil || *cmd.Compensation != compensation {
		t.Fatal("typed recover rejected", err)
	}
	request.Payload = encode(RoutedSelectedV3{Reference: ref})
	_, cmd, err = DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0)
	if err != nil || cmd.Compensation != nil || cmd.Reference != ref {
		t.Fatal("legacy recover rejected", err)
	}
	request.Verb, request.Payload = "prepare_recover", encode(compensation)
	if _, _, err := DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0); err == nil {
		t.Fatal("accepted ticket on prepare")
	}
	request.Verb, request.Payload = "apply", encode(compensation)
	if _, _, err := DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0); err == nil {
		t.Fatal("another action accepted compensation")
	}
	compensation.Selection.WorkHash = digest
	request.Verb, request.Payload = "recover", encode(compensation)
	if _, _, err := DecodeRoutedRequestV3(encode(request), run, request.Namespace, 0); err == nil {
		t.Fatal("accepted a different selected Work")
	}
}
