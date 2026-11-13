package localobserve

// VerifyNoTCPUDPListeners checks complete kernel table captures, including
// wildcard and foreign sockets. Absence grants no ownership or service access.
func VerifyNoTCPUDPListeners(tcp4, tcp6, udp4, udp6 []byte) error {
	for _, table := range []struct {
		data             []byte
		protocol, family string
	}{{tcp4, "tcp", "ipv4"}, {tcp6, "tcp", "ipv6"}, {udp4, "udp", "ipv4"}, {udp6, "udp", "ipv6"}} {
		sockets, err := parseTable(table.data, table.protocol, table.family)
		if err != nil {
			return err
		}
		if len(sockets) != 0 {
			return ErrOwnership
		}
	}
	return nil
}
