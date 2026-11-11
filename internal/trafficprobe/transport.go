package trafficprobe

import (
	"context"
	"net"
	"net/netip"
	"sync"
)

type trace struct {
	mu    sync.Mutex
	items []*transportCount
}

type transportCount struct {
	Transport
	mu sync.Mutex
}

func (t *trace) snapshot() []Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]Transport, 0, len(t.items))
	for _, item := range t.items {
		item.mu.Lock()
		result = append(result, item.Transport)
		item.mu.Unlock()
	}
	return result
}

func (t *trace) dial(ctx context.Context, c Config, protocol string) (net.Conn, error) {
	if protocol != "tcp" && protocol != "udp" {
		return nil, errInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	if len(t.items) >= MaxTransports {
		t.mu.Unlock()
		return nil, errInvalid
	}
	item := &transportCount{Transport: Transport{Protocol: protocol}}
	t.items = append(t.items, item)
	t.mu.Unlock()
	ip := net.IP(c.SourceIPv4.AsSlice())
	dialer := net.Dialer{}
	if protocol == "tcp" {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	} else {
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	}
	conn, err := dialer.DialContext(ctx, protocol+"4", netip.AddrPortFrom(c.TargetIPv4, c.TargetPort).String())
	if err != nil {
		return nil, err
	}
	local, localErr := netip.ParseAddrPort(conn.LocalAddr().String())
	remote, remoteErr := netip.ParseAddrPort(conn.RemoteAddr().String())
	if localErr != nil || remoteErr != nil || local.Addr() != c.SourceIPv4 || remote != netip.AddrPortFrom(c.TargetIPv4, c.TargetPort) {
		_ = conn.Close()
		return nil, errInvalid
	}
	item.mu.Lock()
	item.Connected = true
	item.LocalPort = local.Port()
	item.mu.Unlock()
	wrapped := &countingConn{Conn: conn, count: item}
	wrapped.stopClose = context.AfterFunc(ctx, func() { _ = conn.Close() })
	if packet, ok := conn.(net.PacketConn); ok {
		return &countingPacketConn{countingConn: wrapped, packet: packet}, nil
	}
	return wrapped, nil
}

type countingConn struct {
	net.Conn
	count     *transportCount
	stopClose func() bool
}

func (c *countingConn) Close() error {
	if c.stopClose != nil {
		c.stopClose()
	}
	return c.Conn.Close()
}

func (c *countingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.count.mu.Lock()
	c.count.BytesReceived += int64(n)
	c.count.mu.Unlock()
	return n, err
}

func (c *countingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.count.mu.Lock()
	c.count.BytesSent += int64(n)
	c.count.mu.Unlock()
	return n, err
}

type countingPacketConn struct {
	*countingConn
	packet net.PacketConn
}

func (c *countingPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := c.packet.ReadFrom(data)
	c.count.mu.Lock()
	c.count.BytesReceived += int64(n)
	c.count.mu.Unlock()
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	n, err := c.packet.WriteTo(data, addr)
	c.count.mu.Lock()
	c.count.BytesSent += int64(n)
	c.count.mu.Unlock()
	return n, err
}
