package localobserve

import (
	"errors"
	"testing"
)

func TestEmptyTablesRejectListenersAndMissingCaptures(t *testing.T) {
	empty := [4][]byte{table("tcp", "ipv4", ""), table("tcp", "ipv6", ""), table("udp", "ipv4", ""), table("udp", "ipv6", "")}
	if err := VerifyNoTCPUDPListeners(empty[0], empty[1], empty[2], empty[3]); err != nil {
		t.Fatal(err)
	}
	for i := range empty {
		for _, malformed := range [][]byte{nil, []byte(""), []byte("unrecognized kernel header\n")} {
			input := empty
			input[i] = malformed
			if VerifyNoTCPUDPListeners(input[0], input[1], input[2], input[3]) == nil {
				t.Fatal("missing or malformed table attested as empty", i)
			}
		}
		input := empty
		protocol, family, address := "tcp", "ipv4", "00000000:20FB"
		if i%2 != 0 {
			family, address = "ipv6", "00000000000000000000000000000000:20FB"
		}
		state := "0A"
		if i >= 2 {
			protocol, state = "udp", "07"
		}
		peer := "00000000:0000"
		if family == "ipv6" {
			peer = "00000000000000000000000000000000:0000"
		}
		input[i] = table(protocol, family, row(address, peer, state, 9999, 123))
		if err := VerifyNoTCPUDPListeners(input[0], input[1], input[2], input[3]); !errors.Is(err, ErrOwnership) {
			t.Fatal("foreign wildcard listener accepted", i, err)
		}
	}
}
