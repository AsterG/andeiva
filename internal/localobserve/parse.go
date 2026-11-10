package localobserve

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

func canonicalID(id string) bool {
	if len(id) != 32 {
		return false
	}
	b, err := hex.DecodeString(id)
	return err == nil && hex.EncodeToString(b) == id
}

func namespaceID(link string) (uint64, error) { return bracketID(link, "net:[") }
func bracketID(link, prefix string) (uint64, error) {
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return 0, ErrMalformed
	}
	text := strings.TrimSuffix(strings.TrimPrefix(link, prefix), "]")
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != text {
		return 0, ErrMalformed
	}
	return v, nil
}

func parseStat(data []byte) (int, int, uint64, error) {
	if len(data) == 0 || len(data) > MaxIdentityBytes {
		return 0, 0, 0, ErrMalformed
	}
	text := strings.TrimSuffix(string(data), "\n")
	open := strings.Index(text, " (")
	close := strings.LastIndex(text, ") ")
	if open < 1 || close <= open {
		return 0, 0, 0, ErrMalformed
	}
	pid, err := strconv.Atoi(text[:open])
	if err != nil || pid <= 0 || strconv.Itoa(pid) != text[:open] {
		return 0, 0, 0, ErrMalformed
	}
	fields := strings.Fields(text[close+2:])
	if len(fields) < 20 || len(fields) > 64 || len(fields[0]) != 1 || !strings.Contains("RSDTtI", fields[0]) {
		return 0, 0, 0, ErrMalformed
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent <= 0 || strconv.Itoa(parent) != fields[1] {
		return 0, 0, 0, ErrMalformed
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, 0, 0, ErrMalformed
	}
	return pid, parent, start, nil
}

func parseStatus(data []byte) (uid, gid [4]uint32, parent int, err error) {
	if len(data) == 0 || len(data) > MaxIdentityBytes {
		return uid, gid, 0, ErrMalformed
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			if line != "" {
				return uid, gid, 0, ErrMalformed
			}
			continue
		}
		if key != "Uid" && key != "Gid" && key != "PPid" {
			continue
		}
		if seen[key] {
			return uid, gid, 0, ErrMalformed
		}
		seen[key] = true
		fields := strings.Fields(value)
		if key == "PPid" {
			if len(fields) != 1 {
				return uid, gid, 0, ErrMalformed
			}
			parent, err = strconv.Atoi(fields[0])
			if err != nil || parent <= 0 {
				return uid, gid, 0, ErrMalformed
			}
			continue
		}
		if len(fields) != 4 {
			return uid, gid, 0, ErrMalformed
		}
		var values [4]uint32
		for i, text := range fields {
			v, e := strconv.ParseUint(text, 10, 32)
			if e != nil {
				return uid, gid, 0, ErrMalformed
			}
			values[i] = uint32(v)
		}
		if key == "Uid" {
			uid = values
		} else {
			gid = values
		}
	}
	if len(seen) != 3 {
		return uid, gid, 0, ErrMalformed
	}
	return uid, gid, parent, nil
}

func parseAddress(text, family string) (netip.Addr, uint16, error) {
	address, portText, ok := strings.Cut(text, ":")
	size := 8
	if family == "ipv6" {
		size = 32
	}
	if !ok || len(address) != size || len(portText) != 4 {
		return netip.Addr{}, 0, ErrMalformed
	}
	data, err := hex.DecodeString(address)
	if err != nil {
		return netip.Addr{}, 0, ErrMalformed
	}
	// proc's address words are printed in native byte order; this collector is
	// restricted to the little-endian Debian AMD64 laboratory.
	for offset := 0; offset < len(data); offset += 4 {
		data[offset], data[offset+3] = data[offset+3], data[offset]
		data[offset+1], data[offset+2] = data[offset+2], data[offset+1]
	}
	a, ok := netip.AddrFromSlice(data)
	if !ok {
		return netip.Addr{}, 0, ErrMalformed
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, ErrMalformed
	}
	return a, uint16(port), nil
}

func hexField(text string, width int) bool {
	if len(text) != width {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}

func parseTable(data []byte, protocol, family string) ([]Socket, error) {
	if len(data) == 0 || len(data) > MaxTableBytes || (protocol != "tcp" && protocol != "udp") || (family != "ipv4" && family != "ipv6") {
		return nil, ErrMalformed
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > MaxRows+2 {
		return nil, ErrMalformed
	}
	remote := "rem_address"
	if family == "ipv6" {
		remote = "remote_address"
	}
	header := "sl local_address " + remote + " st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if protocol == "udp" {
		header += " ref pointer drops"
	}
	if strings.Join(strings.Fields(string(lines[0])), " ") != header {
		return nil, ErrMalformed
	}
	result := []Socket{}
	for index, line := range lines[1:] {
		if len(line) == 0 {
			if index != len(lines)-2 {
				return nil, ErrMalformed
			}
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 12 || len(fields) > 20 {
			return nil, ErrMalformed
		}
		if !strings.HasSuffix(fields[0], ":") {
			return nil, ErrMalformed
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 32); err != nil {
			return nil, ErrMalformed
		}
		address, port, err := parseAddress(fields[1], family)
		if err != nil {
			return nil, err
		}
		peer, peerPort, err := parseAddress(fields[2], family)
		if err != nil {
			return nil, err
		}
		if !hexField(fields[3], 2) {
			return nil, ErrMalformed
		}
		state, _ := strconv.ParseUint(fields[3], 16, 8)
		if protocol == "tcp" && (state < 1 || state > 12) || protocol == "udp" && state != 1 && state != 7 {
			return nil, ErrMalformed
		}
		queue := strings.Split(fields[4], ":")
		timer := strings.Split(fields[5], ":")
		if len(queue) != 2 || !hexField(queue[0], 8) || !hexField(queue[1], 8) || len(timer) != 2 || !hexField(timer[0], 2) || !hexField(timer[1], 8) || !hexField(fields[6], 8) {
			return nil, ErrMalformed
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, ErrMalformed
		}
		if _, err := strconv.ParseUint(fields[8], 10, 64); err != nil {
			return nil, ErrMalformed
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, ErrMalformed
		}
		if _, err := strconv.ParseUint(fields[10], 10, 64); err != nil {
			return nil, ErrMalformed
		}
		if !hexField(fields[11], 16) {
			return nil, ErrMalformed
		}
		for _, tail := range fields[12:] {
			if _, err := strconv.ParseInt(tail, 10, 64); err != nil {
				return nil, ErrMalformed
			}
		}
		if protocol == "tcp" && state != 10 {
			continue
		}
		if port == 0 || inode == 0 {
			return nil, ErrMalformed
		}
		if protocol == "tcp" && (!peer.IsUnspecified() || peerPort != 0) {
			return nil, ErrMalformed
		}
		result = append(result, Socket{Protocol: protocol, Family: family, Address: address.String(), Port: port, Inode: inode, UID: uint32(uid), Wildcard: address.IsUnspecified(), Mapped: address.Is4In6()})
	}
	return result, nil
}

func correlate(c capture, expected Expected, start uint64) (Snapshot, error) {
	if c.identity.start != start || c.identity.namespace != expected.Namespace {
		return Snapshot{}, ErrIdentity
	}
	for _, u := range c.identity.uid {
		if u != expected.UID {
			return Snapshot{}, ErrIdentity
		}
	}
	for _, g := range c.identity.gid {
		if g != expected.GID {
			return Snapshot{}, ErrIdentity
		}
	}
	own := map[uint64]bool{}
	for _, fd := range c.fds {
		own[fd.inode] = true
	}
	result := Snapshot{RunID: expected.RunID, Instance: expected.Instance, Generation: expected.Generation, Namespace: expected.Namespace, StartTime: start, Sockets: []Socket{}, Foreign: []Socket{}}
	inodes, tuples := map[uint64]bool{}, map[string]bool{}
	for _, socket := range c.sockets {
		a, err := netip.ParseAddr(socket.Address)
		if err != nil {
			return Snapshot{}, ErrMalformed
		}
		key := fmt.Sprintf("%s/%s/%d", socket.Protocol, a.Unmap(), socket.Port)
		if inodes[socket.Inode] || tuples[key] {
			return Snapshot{}, ErrMalformed
		}
		inodes[socket.Inode] = true
		tuples[key] = true
		if own[socket.Inode] {
			if socket.UID != expected.UID {
				return Snapshot{}, ErrOwnership
			}
			result.Sockets = append(result.Sockets, socket)
		} else {
			result.Foreign = append(result.Foreign, socket)
		}
	}
	return result, nil
}

func sortCapture(c *capture) {
	slices.SortFunc(c.sockets, func(a, b Socket) int {
		if a.Inode < b.Inode {
			return -1
		}
		if a.Inode > b.Inode {
			return 1
		}
		return 0
	})
	slices.SortFunc(c.fds, func(a, b socketFD) int { return a.fd - b.fd })
}

func verifyStable(first, second capture, expected Expected, start uint64) (Snapshot, error) {
	if first.identity != second.identity || !slices.Equal(first.sockets, second.sockets) {
		return Snapshot{}, ErrUnstable
	}
	before, err := correlate(first, expected, start)
	if err != nil {
		return Snapshot{}, err
	}
	after, err := correlate(second, expected, start)
	if err != nil {
		return Snapshot{}, err
	}
	// Accepted connections and inherited host sockets are not local listeners.
	// Require the same listener inodes and ownership in both captures, without
	// treating unrelated descriptor churn as a policy change.
	if !reflect.DeepEqual(before, after) {
		return Snapshot{}, ErrUnstable
	}
	return after, nil
}
