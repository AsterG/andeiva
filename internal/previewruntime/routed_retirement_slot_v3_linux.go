//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

const routedRetirementSlotV3 = "grouped-retirement-v3"
const routedRetirementDirectoryV3 = "/var/lib/andeiva-preview-package"

// PrepareRoutedRetirementSlotV3 is an explicit installer preflight. The service
// may write only this preallocated file, not its containing identity registry.
func PrepareRoutedRetirementSlotV3(ctx context.Context, c Config) error {
	if ctx == nil || ctx.Err() != nil || c.Validate() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || safeParents(routedRetirementDirectoryV3+"/"+routedRetirementSlotV3) != nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return err
	}
	defer area.Close()
	slot, err := openRoutedRetirementSlotV3(area)
	if err != nil {
		return err
	}
	return slot.Close()
}

// This is a bounded operational witness, separate from selected configuration.
// The descriptor stays pinned from preflight until the namespace is drained.
type routedRetirementSlot struct {
	file *os.File
	area *os.Root
}

func openRoutedRetirementSlotV3(area *os.Root) (*routedRetirementSlot, error) {
	if area == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	directory, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|0700 || parent.Uid != 0 || parent.Gid != 0 || !fenceNoACLV3(directory, true) {
		return nil, ErrIdentity
	}
	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	file, err := area.OpenFile(routedRetirementSlotV3, flags|os.O_CREATE|os.O_EXCL, 0600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = area.OpenFile(routedRetirementSlotV3, flags, 0)
	}
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = file.Close()
		}
	}()
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	if created {
		// Reserve actual space before traffic effects, not sparse-file capacity.
		// Failure retains the incomplete slot and requires explicit recovery.
		if err = unix.Fallocate(int(file.Fd()), 0, 0, RootRetirementReceiptSizeV3); err != nil {
			return nil, err
		}
		if err = file.Sync(); err != nil {
			return nil, err
		}
		if err = directory.Sync(); err != nil {
			return nil, err
		}
	}
	if validateRoutedRetirementFileV3(file) != nil {
		return nil, ErrIdentity
	}
	raw := make([]byte, RootRetirementReceiptSizeV3)
	if _, err = file.ReadAt(raw, 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		if _, err = DecodeRootRetirementReceiptV3(raw); err != nil {
			return nil, err
		}
	}
	accepted = true
	return &routedRetirementSlot{file: file, area: area}, nil
}

func validateRoutedRetirementFileV3(file *os.File) error {
	var st unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Size != RootRetirementReceiptSizeV3 || st.Blocks < RootRetirementReceiptSizeV3/512 || !fenceNoACLV3(file, false) {
		return ErrIdentity
	}
	return nil
}

// recordDrained must be called only after child Wait and namespace Close have
// succeeded. No public request or arbitrary receipt can invoke it.
func (s *routedRetirementSlot) recordDrained(metadata Metadata, ids Identities) error {
	if s == nil || os.Getuid() != 0 || os.Geteuid() != 0 || metadata.SchemaVersion != RoutedMetadataSchemaVersion || ids.Validate() != nil || s.sameFile() != nil {
		return ErrIdentity
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return err
	}
	digest := sha256.Sum256(marshal(metadata))
	identity := networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: metadata.GatewayNamespace, Host: metadata.HostNamespace, BootID: metadata.BootID, RunID: metadata.RunID}
	receipt := RootRetirementReceiptV3{Version: 3, Old: identity, MetadataSHA256: hex.EncodeToString(digest[:]), DrainedAtBootNS: now.Nano()}
	raw, err := EncodeRootRetirementReceiptV3(receipt)
	if err != nil {
		return err
	}
	n, err := s.file.WriteAt(raw, 0)
	if err != nil || n != len(raw) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err = s.file.Sync(); err != nil {
		return err
	}
	readback := make([]byte, len(raw))
	if _, err = s.file.ReadAt(readback, 0); err != nil || !bytes.Equal(raw, readback) {
		return errors.Join(err, ErrStorage)
	}
	return s.sameFile()
}

func (s *routedRetirementSlot) sameFile() error {
	if s == nil || s.area == nil || validateRoutedRetirementFileV3(s.file) != nil {
		return ErrIdentity
	}
	current, err := s.area.Lstat(routedRetirementSlotV3)
	if err != nil {
		return ErrIdentity
	}
	pinned, err := s.file.Stat()
	if err != nil || !os.SameFile(current, pinned) {
		return ErrIdentity
	}
	return nil
}

func (s *routedRetirementSlot) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
