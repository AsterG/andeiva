//go:build linux && andeiva_native_dhcp_diagnostics

package dhcpclient

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const clientDiagnosticLimit = 64 << 10

type clientDiagnostic struct {
	mu        sync.Mutex
	file      *os.File
	written   int
	truncated bool
}

func openClientDiagnostic() (*clientDiagnostic, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrScope
	}
	fd, err := unix.Open("/run/andeiva-dhcp", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, ErrScope
	}
	return openClientDiagnosticAt(fd, 0)
}

func openClientDiagnosticAt(parent int, uid uint32) (*clientDiagnostic, error) {
	var st unix.Stat_t
	if unix.Fstat(parent, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0022 != 0 {
		return nil, ErrScope
	}
	if err := unix.Mkdirat(parent, "native-diagnostics", 0700); err != nil {
		return nil, err
	}
	dir, err := unix.Openat(parent, "native-diagnostics", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	if unix.Fstat(dir, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uid {
		return nil, ErrScope
	}
	fd, err := unix.Openat(dir, "events.jsonl", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "native-dhcp-diagnostic")
	if unix.Fchmod(fd, 0600) != nil || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uid || st.Nlink != 1 {
		_ = f.Close()
		return nil, ErrScope
	}
	return &clientDiagnostic{file: f}, nil
}

func (d *clientDiagnostic) event(stage, detail string, code int) {
	d.writeEvent(stage, detail, code, 0)
}

func (d *clientDiagnostic) leaseEvent(e Event) {
	if e.validate() != nil {
		return
	}
	d.writeEvent("event", e.Reason, 0, e.Seconds)
}

func (d *clientDiagnostic) writeEvent(stage, detail string, code int, seconds uint32) {
	if d == nil {
		return
	}
	now, err := bootNow()
	if err != nil {
		return
	}
	data, err := json.Marshal(struct {
		BootNS       int64  `json:"boot_ns"`
		Stage        string `json:"stage"`
		Detail       string `json:"detail,omitempty"`
		Code         int    `json:"code,omitempty"`
		LeaseSeconds uint32 `json:"lease_seconds,omitempty"`
	}{now, stage, detail, code, seconds})
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil || d.truncated {
		return
	}
	data = append(data, '\n')
	if len(data) > 512 || d.written+len(data) > clientDiagnosticLimit-64 {
		data = []byte("{\"stage\":\"truncated\"}\n")
		d.truncated = true
	}
	n, err := d.file.Write(data)
	d.written += n
	if err != nil || n != len(data) {
		d.truncated = true
	}
}

func (d *clientDiagnostic) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
}

func (d *clientDiagnostic) stderr() io.Writer { return &clientDiagnosticStderr{diagnostic: d} }

type clientDiagnosticStderr struct {
	diagnostic *clientDiagnostic
	line       [1024]byte
	used       int
}

// Only fixed classifications survive. Addresses, options, hostnames and raw
// engine output never enter the diagnostic file or the hook stdout protocol.
func (w *clientDiagnosticStderr) Write(p []byte) (int, error) {
	w.diagnostic.mu.Lock()
	discard := w.diagnostic.truncated || w.diagnostic.file == nil
	w.diagnostic.mu.Unlock()
	if discard {
		return len(p), nil
	}
	for _, b := range p {
		if b == '\n' {
			w.diagnostic.event("stderr", clientDiagnosticClass(string(w.line[:w.used])), 0)
			w.used = 0
		} else if w.used < len(w.line) {
			w.line[w.used] = b
			w.used++
		}
	}
	return len(p), nil
}

func clientDiagnosticClass(line string) string {
	line = strings.ToLower(line)
	for _, entry := range []struct{ text, code string }{
		{"operation not permitted", "permission"}, {"permission denied", "permission"},
		{"address family not supported", "socket_family"}, {"no such file", "missing_file"},
		{"invalid argument", "invalid_argument"}, {"address already in use", "address_in_use"},
		{"no buffer space", "socket_buffer"}, {"offered ", "offer"}, {"leased ", "lease"},
		{"soliciting", "solicit"}, {"waiting for carrier", "carrier_wait"}, {"carrier acquired", "carrier_up"},
		{"script", "hook"}, {"seccomp", "seccomp"}, {"chroot", "chroot"},
		{"exited", "exit"}, {"dhcpcd-", "engine_start"},
	} {
		if strings.Contains(line, entry.text) {
			return entry.code
		}
	}
	return "unclassified"
}
