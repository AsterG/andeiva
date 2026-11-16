package localobserve

import "testing"

func TestParseSocketTablesPreservesForeignAndIPv6(t *testing.T) {
	tcp4 := table("tcp", "ipv4", row("00000000:20FB", "00000000:0000", "0A", 42, 1))
	tcp6 := table("tcp", "ipv6", row("00000000000000000000000000000000:20FB", "00000000000000000000000000000000:0000", "0A", 43, 2))
	udp4 := table("udp", "ipv4", row("0A0112C6:0044", "00000000:0000", "07", 0, 3))
	udp6 := table("udp", "ipv6", row("00000000000000000000000000000000:0044", "00000000000000000000000000000000:0000", "07", 0, 4))
	rows, err := ParseSocketTables(tcp4, tcp6, udp4, udp6)
	if err != nil || len(rows) != 4 || rows[0].UID != 42 || rows[1].Family != "ipv6" || rows[2].Address != "198.18.1.10" || !rows[3].Wildcard {
		t.Fatalf("inventory lost entries: %v %v", rows, err)
	}
	if _, err = ParseSocketTables(tcp4, tcp6, nil, udp6); err == nil {
		t.Fatal("missing table accepted")
	}
	if _, err = ParseSocketTables(tcp4, tcp6, table("udp", "ipv4", row("0A0112C6:0044", "00000000:0000", "07", 0, 1)), udp6); err == nil {
		t.Fatal("duplicate inode accepted")
	}
}
