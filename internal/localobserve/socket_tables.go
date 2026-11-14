package localobserve

// ParseSocketTables returns every TCP listener and bound UDP socket in the
// four complete kernel tables. It grants no ownership and filters no service.
func ParseSocketTables(tcp4, tcp6, udp4, udp6 []byte) ([]Socket, error) {
	result := []Socket{}
	seen := map[uint64]bool{}
	for _, table := range []struct {
		data             []byte
		protocol, family string
	}{{tcp4, "tcp", "ipv4"}, {tcp6, "tcp", "ipv6"}, {udp4, "udp", "ipv4"}, {udp6, "udp", "ipv6"}} {
		rows, err := parseTable(table.data, table.protocol, table.family)
		if err != nil {
			return nil, err
		}
		if len(result)+len(rows) > MaxRows {
			return nil, ErrMalformed
		}
		for _, s := range rows {
			if seen[s.Inode] {
				return nil, ErrUnstable
			}
			seen[s.Inode] = true
			result = append(result, s)
		}
	}
	return result, nil
}
