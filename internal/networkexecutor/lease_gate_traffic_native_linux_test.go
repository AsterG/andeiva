//go:build linux

package networkexecutor

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const gateTrafficPhasePath = "/run/andeiva-lease/traffic-phase"

// These roles exchange real packets. Root owns all namespace setup and phase
// evidence; these processes have no capabilities and cannot write that evidence.
func nativeGateTrafficProfile(t *testing.T, role string) {
	t.Helper()
	if os.Getenv("ANDEIVA_LEASE_NATIVE") != "1" || os.Getenv("ANDEIVA_LEASE_ROLE") != role {
		t.Skip("requires authorized isolated gate-traffic harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 62007 || os.Getgid() != 62007 {
		t.Fatal("traffic identity refused")
	}
	version, err := os.ReadFile("/proc/version")
	if err != nil || strings.Contains(strings.ToLower(string(version)), "microsoft") {
		t.Fatal("native platform refused")
	}
	status, err := readOwnedIdentityFile(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateTrafficCapless(status); err != nil {
		t.Fatal(err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range groups {
		if gid != 62007 {
			t.Fatal("unexpected group")
		}
	}
	var ids [2]uint64
	for i, fd := range []int{3, 4} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("namespace pin access")
		}
		ids[i], err = namespaceID(fd)
		if err != nil {
			t.Fatal("namespace pin type")
		}
		unix.CloseOnExec(fd)
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	id, err := namespaceID(int(self.Fd()))
	if err != nil || ids[0] == ids[1] || id == ids[0] || id == ids[1] {
		t.Fatal("traffic namespace is host or gateway")
	}
	t.Logf("traffic role=%s uid=62007 gid=62007 caps=0 nnp=1 namespace=%d", role, id)
}

func gateTrafficCapless(status []byte) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, _ := strings.Cut(line, ":")
		switch key {
		case "Uid", "Gid":
			if seen[key] || strings.Join(strings.Fields(value), " ") != "62007 62007 62007 62007" {
				return ErrScope
			}
			seen[key] = true
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if seen[key] || strings.TrimSpace(value) != "0000000000000000" {
				return ErrScope
			}
			seen[key] = true
		case "NoNewPrivs":
			if seen[key] || strings.TrimSpace(value) != "1" {
				return ErrScope
			}
			seen[key] = true
		}
	}
	if len(seen) != 8 {
		return ErrScope
	}
	return nil
}

func gateTrafficPhase() (string, error) {
	fd, err := unix.Open(gateTrafficPhasePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "root-traffic-phase")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0644 || st.Size > 16 {
		return "", ErrScope
	}
	b, err := io.ReadAll(io.LimitReader(f, 17))
	if err != nil {
		return "", err
	}
	switch string(b) {
	case "before\n", "expired\n", "stop\n":
		return string(b), nil
	}
	return "", ErrScope
}

func gateTrafficWait(want string, limit time.Duration) error {
	until := time.Now().Add(limit)
	for time.Now().Before(until) {
		phase, err := gateTrafficPhase()
		if err != nil {
			return err
		}
		if phase == want {
			return nil
		}
		if phase == "stop\n" {
			return ErrScope
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ErrCommand
}

func TestNativeLeaseGateTrafficServer(t *testing.T) {
	nativeGateTrafficProfile(t, "traffic-server")
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.19.0.2"), Port: 18080})
	if err != nil {
		t.Fatal("tcp listen", err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.0.2"), Port: 18081})
	if err != nil {
		t.Fatal("udp listen", err)
	}
	defer udp.Close()
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		// One accepted TCP connection is retained across token expiry. A server
		// exit/reset must fail the client; only read timeouts qualify denial.
		_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
		conn, err := tcp.AcceptTCP()
		if err != nil {
			errorsCh <- err
			return
		}
		defer conn.Close()
		if conn.RemoteAddr().(*net.TCPAddr).IP.String() != "198.18.0.2" {
			errorsCh <- ErrScope
			return
		}
		var frame [32]byte
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := io.ReadFull(conn, frame[:])
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() && n == 0 {
				continue
			}
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				errorsCh <- err
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err = conn.Write(frame[:]); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		var frame [33]byte
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, err := udp.ReadFromUDP(frame[:])
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			if err != nil {
				errorsCh <- err
				return
			}
			if n != 32 || peer.IP.String() != "198.18.0.2" {
				errorsCh <- ErrScope
				return
			}
			_ = udp.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err = udp.WriteToUDP(frame[:n], peer); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	t.Log("TRAFFIC_SERVER_READY")
	phaseErr := gateTrafficWait("stop\n", 35*time.Second)
	close(stop)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Error("echo server", err)
		}
	}
	if phaseErr != nil {
		t.Fatal("server phase", phaseErr)
	}
	t.Log("TRAFFIC_SERVER_STOPPED")
}

func gateTrafficProbe(conn net.Conn) error {
	var nonce, reply [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(1200 * time.Millisecond)); err != nil {
		return err
	}
	n, err := conn.Write(nonce[:])
	if err != nil {
		return err
	}
	if n != len(nonce) {
		return io.ErrShortWrite
	}
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if !bytes.Equal(nonce[:], reply[:]) {
		return ErrObservation
	}
	return nil
}

func TestNativeLeaseGateTrafficClient(t *testing.T) {
	nativeGateTrafficProfile(t, "traffic-client")
	if phase, err := gateTrafficPhase(); err != nil || phase != "before\n" {
		t.Fatal("initial traffic phase", phase, err)
	}
	dialer := net.Dialer{Timeout: 1200 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.18.0.2")}, KeepAlive: -1}
	tcp, err := dialer.Dial("tcp4", "198.19.0.2:18080")
	if err != nil {
		t.Fatal("initial TCP", err)
	}
	defer tcp.Close()
	udp, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2")}, &net.UDPAddr{IP: net.ParseIP("198.19.0.2"), Port: 18081})
	if err != nil {
		t.Fatal("initial UDP", err)
	}
	defer udp.Close()
	if err := gateTrafficProbe(tcp); err != nil {
		t.Fatal("TCP before expiry", err)
	}
	if err := gateTrafficProbe(udp); err != nil {
		t.Fatal("UDP before expiry", err)
	}
	t.Log("TRAFFIC_PRE_EXPIRY_PASS")
	if err := gateTrafficWait("expired\n", 18*time.Second); err != nil {
		t.Fatal("expiry phase", err)
	}
	for name, conn := range map[string]net.Conn{"established TCP": tcp, "UDP": udp} {
		err := gateTrafficProbe(conn)
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("%s did not time out after kernel expiry: %v", name, err)
		}
	}
	newConn, err := dialer.Dial("tcp4", "198.19.0.2:18080")
	if newConn != nil {
		_ = newConn.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("new TCP did not time out: %v", err)
	}
	t.Log("TRAFFIC_POST_EXPIRY_PASS")
}

func TestLeaseGateTrafficCaplessProfile(t *testing.T) {
	status := "Uid:\t62007\t62007\t62007\t62007\nGid:\t62007\t62007\t62007\t62007\nNoNewPrivs:\t1\n"
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		status += key + ":\t0000000000000000\n"
	}
	if gateTrafficCapless([]byte(status)) != nil {
		t.Fatal("valid capless profile")
	}
	for _, bad := range []string{strings.Replace(status, "0000000000000000", "0000000000001000", 1), strings.Replace(status, "62007", "0", 1), status + "CapEff:\t0000000000000000\n", strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)} {
		if gateTrafficCapless([]byte(bad)) == nil {
			t.Fatal("invalid traffic role accepted")
		}
	}
}

func TestLeaseGateTrafficProbeRequiresFreshEcho(t *testing.T) {
	for _, mode := range []string{"echo", "wrong", "closed"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				if mode == "closed" {
					return
				}
				var data [32]byte
				if _, err := io.ReadFull(server, data[:]); err != nil {
					return
				}
				if mode == "wrong" {
					data[0] ^= 1
				}
				_, _ = server.Write(data[:])
			}()
			err := gateTrafficProbe(client)
			<-done
			if (mode == "echo") != (err == nil) {
				t.Fatal("echo classification", mode, err)
			}
			var timeout net.Error
			if mode != "echo" && errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("bad echo or closed server counted as timeout")
			}
		})
	}
}
