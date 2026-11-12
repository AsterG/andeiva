package recoveryreserve

import (
	"context"
	"io"
	"os"
)

// CheckDirectory validates a pinned root's metadata without opening any record.
// It neither grants caller authority nor verifies a canonical feature marker.
func (a ReaderAccessV2) CheckDirectory(area *os.Root) error {
	if area == nil || !a.valid() {
		return ErrInvalid
	}
	i, err := area.Stat(".")
	if err != nil || !accessDirectoryV2(area, i, &a) {
		return ErrUnavailable
	}
	return nil
}

func readerBasenameV2(name string) bool {
	if len(name) < 1 || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if c != '.' && c != '-' && c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ReadFile is a bounded filesystem primitive shared with selected-state readers.
// Callers must validate content hashes, types, contextual edges and selection.
// Cancellation is cooperative; it cannot interrupt a blocked filesystem syscall.
func (a ReaderAccessV2) ReadFile(ctx context.Context, area *os.Root, basename string, maxBytes int) (data []byte, result error) {
	if ctx == nil || !readerBasenameV2(basename) || maxBytes < 1 || maxBytes > 1<<20 || !a.valid() || !accessReaderV2(a) || area == nil {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil || a.CheckDirectory(area) != nil {
		return nil, ErrUnavailable
	}
	root, err := area.Stat(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	before, err := area.Lstat(basename)
	if err != nil {
		return nil, ErrUnavailable
	}
	f, err := openAccessFileV2(area, basename, true)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if f.Close() != nil {
			data, result = nil, ErrUnavailable
		}
	}()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || !accessFileV2(f, info, root, &a) {
		return nil, ErrUnavailable
	}
	size := info.Size()
	if size < 0 || size > int64(maxBytes) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	buffer := make([]byte, size+1)
	n, err := f.ReadAt(buffer, 0)
	if err != io.EOF || int64(n) != size {
		return nil, ErrUnavailable
	}
	after, err := f.Stat()
	if err != nil || !accessFileV2(f, after, root, &a) || after.Size() != size || !after.ModTime().Equal(info.ModTime()) {
		return nil, ErrUnavailable
	}
	named, err := area.Lstat(basename)
	if err != nil || !os.SameFile(named, after) || !accessFileV2(f, named, root, &a) || named.Size() != size || ctx.Err() != nil || a.CheckDirectory(area) != nil {
		return nil, ErrUnavailable
	}
	return buffer[:n:n], nil
}
