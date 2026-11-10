package localobserve

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func table(protocol, family, row string) []byte {
	remote := "rem_address"
	if family == "ipv6" {
		remote = "remote_address"
	}
	header := "sl local_address " + remote + " st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if protocol == "udp" {
		header += " ref pointer drops"
	}
	return []byte(header + "\n" + row)
}
func row(address, peer, state string, uid, inode uint64) string {
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 %d 0 %d 1 0000000000000000 100 0 0 10 0\n", address, peer, state, uid, inode)
}

func TestLittleEndianAddressesAndMappedWildcards(t *testing.T) {
	for _, tc := range []struct {
		text, family, want string
		port               uint16
	}{
		{"020112C6:20FB", "ipv4", "198.18.1.2", 8443},
		{"00000000:0000", "ipv4", "0.0.0.0", 0},
		{"0100007F:0050", "ipv4", "127.0.0.1", 80},
		{"00000000000000000000000001000000:08AE", "ipv6", "::1", 2222},
		{"0000000000000000FFFF0000020112C6:20FB", "ipv6", "::ffff:198.18.1.2", 8443},
		{"6E6142FD010065640000000001000000:20FB", "ipv6", "fd42:616e:6465:1::1", 8443},
	} {
		a, p, err := parseAddress(tc.text, tc.family)
		if err != nil || a.String() != tc.want || p != tc.port {
			t.Fatal(tc, a, p, err)
		}
	}
	data := table("tcp", "ipv6", row("0000000000000000FFFF0000020112C6:20FB", "00000000000000000000000000000000:0000", "0A", 1001, 70))
	parsed, err := parseTable(data, "tcp", "ipv6")
	if err != nil || !parsed[0].Mapped || parsed[0].Wildcard {
		t.Fatal(parsed, err)
	}
	data = table("tcp", "ipv4", row("00000000:20FB", "00000000:0000", "0A", 1001, 71))
	parsed, err = parseTable(data, "tcp", "ipv4")
	if err != nil || !parsed[0].Wildcard {
		t.Fatal(parsed, err)
	}
}

func TestTablesFilterEstablishedButRetainBoundUDP(t *testing.T) {
	for _, state := range []string{"01", "07", "06"} {
		data := table("tcp", "ipv4", row("0100007F:20FB", "0200007F:ABCD", state, 1001, 0))
		parsed, err := parseTable(data, "tcp", "ipv4")
		if err != nil || len(parsed) != 0 {
			t.Fatal("nonlistener", parsed, err)
		}
	}
	for _, state := range []string{"01", "07"} {
		data := table("udp", "ipv4", row("0100007F:20FB", "0200007F:ABCD", state, 1001, 77))
		parsed, err := parseTable(data, "udp", "ipv4")
		if err != nil || len(parsed) != 1 {
			t.Fatal("bound UDP disappeared", parsed, err)
		}
	}
}

func TestMalformedRowsHeadersAndBudgetsFailClosed(t *testing.T) {
	valid := string(table("tcp", "ipv4", row("0100007F:20FB", "00000000:0000", "0A", 1001, 77)))
	bad := []string{"", strings.Replace(valid, "rem_address", "remote_address", 1), strings.Replace(valid, "0: ", "x: ", 1), strings.Replace(valid, "0100007F", "GG00007F", 1), strings.Replace(valid, "20FB", "FFFFF", 1), strings.Replace(valid, " 0A ", " 0Z ", 1), strings.Replace(valid, "00000000:00000000", "0000000:00000000", 1), strings.Replace(valid, " 1001 ", " 4294967296 ", 1), strings.Replace(valid, " 77 ", " 0 ", 1), strings.Replace(valid, "00000000:0000", "0200007F:0000", 1), strings.Replace(valid, " 77 ", " -1 ", 1), valid + "unknown\n", strings.Repeat("x", MaxTableBytes+1)}
	for _, data := range bad {
		if _, err := parseTable([]byte(data), "tcp", "ipv4"); err == nil {
			t.Fatalf("accepted malformed %.100q", data)
		}
	}
	tooMany := table("tcp", "ipv4", strings.Repeat(row("0100007F:20FB", "00000000:0000", "0A", 1001, 77), MaxRows+1))
	if _, err := parseTable(tooMany, "tcp", "ipv4"); err == nil {
		t.Fatal("row budget ignored")
	}
}

func expected() Expected {
	return Expected{UID: 1001, GID: 1002, Namespace: 22, HostNamespace: 11, RunID: strings.Repeat("a", 32), Instance: strings.Repeat("b", 32), Generation: 1}
}
func baseCapture() capture {
	return capture{identity: processIdentity{pid: 123, parent: 42, start: 99, uid: [4]uint32{1001, 1001, 1001, 1001}, gid: [4]uint32{1002, 1002, 1002, 1002}, namespace: 22}, sockets: []Socket{{Protocol: "tcp", Family: "ipv4", Address: "198.18.1.1", Port: 8443, Inode: 77, UID: 1001}}, fds: []socketFD{{4, 77}}}
}

func TestCorrelationRequiresOwnedInodeNotUIDAndTuple(t *testing.T) {
	c := baseCapture()
	result, err := correlate(c, expected(), 99)
	if err != nil || len(result.Sockets) != 1 || len(result.Foreign) != 0 {
		t.Fatal(result, err)
	}
	c.fds = []socketFD{{4, 88}}
	result, err = correlate(c, expected(), 99)
	if err != nil || len(result.Sockets) != 0 || len(result.Foreign) != 1 {
		t.Fatal("same UID/tuple attributed without FD", result, err)
	}
	c = baseCapture()
	c.sockets[0].UID = 0
	if _, err := correlate(c, expected(), 99); !errors.Is(err, ErrOwnership) {
		t.Fatal("FD UID mismatch", err)
	}
	c = baseCapture()
	c.fds = append(c.fds, socketFD{8, 999})
	result, err = correlate(c, expected(), 99)
	if err != nil || len(result.Sockets) != 1 {
		t.Fatal("unlisted host recovery FD must not become gateway listener", result, err)
	}
	for _, change := range []func(*capture){func(c *capture) { c.identity.start++ }, func(c *capture) { c.identity.namespace++ }, func(c *capture) { c.identity.uid[1]++ }, func(c *capture) { c.identity.gid[2]++ }} {
		c := baseCapture()
		change(&c)
		if _, err := correlate(c, expected(), 99); !errors.Is(err, ErrIdentity) {
			t.Fatal("changed identity accepted", err)
		}
	}
}

func TestDuplicatesMappedAliasesAndMultipleReadsRejected(t *testing.T) {
	for _, second := range []Socket{
		{Protocol: "tcp", Family: "ipv4", Address: "198.18.1.1", Port: 8443, Inode: 78, UID: 1001},
		{Protocol: "tcp", Family: "ipv6", Address: "::ffff:198.18.1.1", Port: 8443, Inode: 78, UID: 1001, Mapped: true},
		{Protocol: "tcp", Family: "ipv4", Address: "198.18.1.2", Port: 8443, Inode: 77, UID: 1001},
	} {
		c := baseCapture()
		c.sockets = append(c.sockets, second)
		if _, err := correlate(c, expected(), 99); err == nil {
			t.Fatal("duplicate accepted", second)
		}
	}
	a, b := baseCapture(), baseCapture()
	if _, err := verifyStable(a, b, expected(), 99); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*capture){func(c *capture) { c.identity.start++ }, func(c *capture) { c.identity.pid++ }, func(c *capture) { c.identity.parent++ }, func(c *capture) { c.sockets[0].Inode++ }, func(c *capture) { c.fds[0].inode++ }, func(c *capture) { c.fds = nil }} {
		b := baseCapture()
		change(&b)
		if _, err := verifyStable(a, b, expected(), 99); !errors.Is(err, ErrUnstable) {
			t.Fatal("unstable capture accepted", err)
		}
	}
}

func TestProcessIdentityParsers(t *testing.T) {
	fields := []string{"S", "42"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, "99", "0")
	stat := "123 (a tricky ) name) " + strings.Join(fields, " ") + "\n"
	pid, parent, start, err := parseStat([]byte(stat))
	if err != nil || pid != 123 || parent != 42 || start != 99 {
		t.Fatal(pid, parent, start, err)
	}
	status := "Name:\ttest\nPPid:\t42\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n"
	uid, gid, ppid, err := parseStatus([]byte(status))
	if err != nil || ppid != 42 || uid != [4]uint32{1001, 1001, 1001, 1001} || gid != [4]uint32{1002, 1002, 1002, 1002} {
		t.Fatal(uid, gid, ppid, err)
	}
	for _, bad := range []string{status + "Uid:\t0 0 0 0\n", strings.Replace(status, "1001", "-1", 1), "Uid: 1 1 1 1\n", strings.Repeat("x", MaxIdentityBytes+1)} {
		if _, _, _, err := parseStatus([]byte(bad)); err == nil {
			t.Fatal("bad status accepted")
		}
	}
	for _, bad := range []string{"", strings.Replace(stat, ") S ", ") Z ", 1), strings.Replace(stat, " 99 ", " 0 ", 1), strings.Repeat("x", MaxIdentityBytes+1)} {
		if _, _, _, err := parseStat([]byte(bad)); err == nil {
			t.Fatal("bad stat accepted")
		}
	}
	for _, id := range []string{"net:[0]", "net:[01]", "socket:[2]", "net:[18446744073709551616]", "net:[1]/../../"} {
		if _, err := namespaceID(id); err == nil {
			t.Fatal("namespace accepted", id)
		}
	}
	if !canonicalID(strings.Repeat("a", 32)) || canonicalID(strings.Repeat("A", 32)) || canonicalID("../") {
		t.Fatal("identity format")
	}
}

func TestStableListenersIgnoreUnrelatedSocketFDChurn(t *testing.T) {
	first, second := baseCapture(), baseCapture()
	first.fds = append(first.fds, socketFD{8, 888})
	second.fds = append(second.fds, socketFD{9, 999})
	got, err := verifyStable(first, second, expected(), 99)
	if err != nil || len(got.Sockets) != 1 || len(got.Foreign) != 0 {
		t.Fatalf("nonlistener churn invalidated stable owned listener: %+v %v", got, err)
	}
	// FD numbers are not ownership: a duplicate can retain the same inode.
	second.fds = []socketFD{{10, 77}}
	if _, err := verifyStable(first, second, expected(), 99); err != nil {
		t.Fatal("same listener inode held under a different FD", err)
	}
}

func TestStableCapturePreservesForeignListenersAndOwnershipFailures(t *testing.T) {
	first, second := baseCapture(), baseCapture()
	first.fds, second.fds = nil, nil
	got, err := verifyStable(first, second, expected(), 99)
	if err != nil || len(got.Sockets) != 0 || len(got.Foreign) != 1 {
		t.Fatal("unowned listener must remain foreign", got, err)
	}
	for _, mutate := range []func(*capture){
		func(c *capture) { c.sockets = nil },
		func(c *capture) { c.sockets[0].Port++ },
		func(c *capture) { c.sockets[0].UID++ },
		func(c *capture) { c.fds = []socketFD{{6, 77}} },
		func(c *capture) { c.identity.uid[0]++ },
		func(c *capture) { c.identity.gid[3]++ },
		func(c *capture) { c.identity.namespace++ },
	} {
		second := baseCapture()
		second.fds = nil
		mutate(&second)
		if _, err := verifyStable(first, second, expected(), 99); err == nil {
			t.Fatal("changed listener, ownership or identity accepted")
		}
	}
	first, second = baseCapture(), baseCapture()
	first.sockets[0].UID, second.sockets[0].UID = 0, 0
	if _, err := verifyStable(first, second, expected(), 99); !errors.Is(err, ErrOwnership) {
		t.Fatal("stable wrong-UID inode accepted", err)
	}
}
