package recoveryreserve

import "os"

// CheckFile validates only descriptor/name metadata and ACLs, not content or
// durability. It shares the exact profile validator used by the pool reader.
func (a ReaderAccessV2) CheckFile(area *os.Root, basename string, maxBytes int64) (info os.FileInfo, result error) {
	if area == nil || !a.valid() || !readerBasenameV2(basename) || maxBytes < 0 || maxBytes > 1<<20 {
		return nil, ErrInvalid
	}
	if a.CheckDirectory(area) != nil {
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
			info, result = nil, ErrUnavailable
		}
	}()
	info, err = f.Stat()
	if err != nil || !os.SameFile(before, info) || !accessFileV2(f, info, root, &a) || info.Size() < 0 || info.Size() > maxBytes {
		return nil, ErrUnavailable
	}
	named, err := area.Lstat(basename)
	if err != nil || !os.SameFile(named, info) || !accessFileV2(f, named, root, &a) || named.Size() != info.Size() || !named.ModTime().Equal(info.ModTime()) || a.CheckDirectory(area) != nil {
		return nil, ErrUnavailable
	}
	return info, nil
}
