package nftfixture

import "testing"

func TestProbeInputsAreFixed(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for port := 18080; port <= 18082; port++ {
			if !validProbe(protocol, port) {
				t.Fatalf("rejected fixture %s/%d", protocol, port)
			}
		}
	}
	for _, protocol := range []string{"", "icmp", "tcp6", "udp;reboot", "TCP"} {
		if validProbe(protocol, 18080) {
			t.Fatalf("accepted protocol %q", protocol)
		}
	}
	for _, port := range []int{-1, 0, 22, 18079, 18083, 65536} {
		if validProbe("tcp", port) {
			t.Fatalf("accepted port %d", port)
		}
	}
}

func TestRoleParsingRejectsUnexpectedArguments(t *testing.T) {
	if handled, _ := HandleRole([]string{"--unrelated"}); handled {
		t.Fatal("claimed unrelated command")
	}
	for _, args := range [][]string{{"--nft-fixture"}, {"--nft-fixture", "shell"}, {"--nft-fixture", "probe", "icmp", "18080"}, {"--nft-fixture", "probe", "tcp", "22"}, {"--nft-fixture", "probe", "tcp", "18080", "extra"}, {"--nft-fixture", "forward", "invalid"}} {
		handled, code := HandleRole(args)
		if !handled || code != 2 {
			t.Fatalf("accepted malformed role: %v", args)
		}
	}
}
