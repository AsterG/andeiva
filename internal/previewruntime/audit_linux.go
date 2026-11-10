//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

const AuditSegmentBytes int64 = 1 << 20
const AuditSegments = 16

type auditLog struct {
	mu          sync.Mutex
	root        *os.Root
	path        string
	file        *os.File
	size        int64
	segment     int
	uid, gid    uint32
	failed      bool
	maxBytes    int64
	maxSegments int
}

func openAudit(path string, uid, gid uint32) (*auditLog, error) {
	return openAuditBounded(path, uid, gid, AuditSegmentBytes, AuditSegments)
}
func openAuditBounded(path string, uid, gid uint32, maxBytes int64, maxSegments int) (*auditLog, error) {
	if ownedDirectory(path, uid, gid, 0700) != nil {
		return nil, ErrStorage
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrStorage
	}
	a := &auditLog{root: root, path: path, uid: uid, gid: gid, maxBytes: maxBytes, maxSegments: maxSegments}
	entries, e := os.ReadDir(path)
	if e != nil || len(entries) > maxSegments {
		root.Close()
		return nil, ErrStorage
	}
	for i, entry := range entries {
		expected := fmt.Sprintf("%06d.jsonl", i+1)
		if entry.Name() != expected {
			root.Close()
			return nil, ErrStorage
		}
		b, e := readOwned(filepath.Join(path, expected), uid, gid, 0600, maxBytes)
		if e != nil || (len(b) > 0 && b[len(b)-1] != '\n') {
			root.Close()
			return nil, ErrStorage
		}
		scan := bufio.NewScanner(bytes.NewReader(b))
		scan.Buffer(make([]byte, 4096), 4096)
		for scan.Scan() {
			var event adminauth.Event
			if firewallipc.Decode(scan.Bytes(), &event) != nil || event.At.IsZero() {
				root.Close()
				return nil, ErrStorage
			}
		}
		if scan.Err() != nil {
			root.Close()
			return nil, ErrStorage
		}
		a.segment = i + 1
		a.size = int64(len(b))
	}
	if a.segment > 0 {
		a.file, e = root.OpenFile(fmt.Sprintf("%06d.jsonl", a.segment), os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			root.Close()
			return nil, ErrStorage
		}
	}
	return a, nil
}
func (a *auditLog) Append(event adminauth.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return ErrStorage
	}
	b, e := json.Marshal(event)
	if e != nil || len(b) > 4094 {
		return ErrStorage
	}
	b = append(b, '\n')
	if a.file == nil || a.size+int64(len(b)) > a.maxBytes {
		if a.segment >= a.maxSegments {
			a.failed = true
			return ErrStorage
		}
		if a.file != nil {
			if a.file.Close() != nil {
				a.failed = true
				return ErrStorage
			}
			a.file = nil
		}
		a.segment++
		a.size = 0
		a.file, e = a.root.OpenFile(fmt.Sprintf("%06d.jsonl", a.segment), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil || a.file.Chmod(0600) != nil || syncDirectory(a.path) != nil {
			a.failed = true
			return ErrStorage
		}
	}
	n, e := a.file.Write(b)
	a.size += int64(n)
	if e != nil || n != len(b) || a.file.Sync() != nil {
		a.failed = true
		return ErrStorage
	}
	return nil
}
func (a *auditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failed = true
	var e error
	if a.file != nil {
		e = a.file.Close()
	}
	if r := a.root.Close(); e == nil {
		e = r
	}
	return e
}
