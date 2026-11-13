//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const routedSupervisorCgroupV3 = "/system.slice/andeiva-preview-grouped.service"

func finishRoutedScopeRetirementV3(slot *routedRetirementSlot, metadata Metadata, ids Identities, closeNamespace func() error) error {
	if closeNamespace == nil {
		return ErrIdentity
	}
	if err := waitRoutedCgroupDrainedV3(); err != nil {
		return err
	}
	if err := closeNamespace(); err != nil {
		return err
	}
	return slot.recordDrained(metadata, ids)
}

func routedCgroupOnlySupervisorV3(raw []byte, pid int) bool {
	fields := bytes.Fields(raw)
	return pid > 0 && len(fields) == 1 && string(fields[0]) == strconv.Itoa(pid)
}

// Wait of API/helper leaders is insufficient: an executor grandchild may still
// hold the old namespace. Only the dedicated, non-delegated service cgroup can
// establish that every other process has exited before namespace retirement.
func waitRoutedCgroupDrainedV3() error {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"\n" {
		return ErrIdentity
	}
	area, err := os.OpenRoot("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		return err
	}
	defer area.Close()
	directory, err := area.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil || len(entries) > 256 {
		return ErrIdentity
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrIdentity
		}
	}
	kind, err := area.ReadFile("cgroup.type")
	if err != nil || string(kind) != "domain\n" {
		return ErrIdentity
	}
	subtree, err := area.ReadFile("cgroup.subtree_control")
	if err != nil || strings.TrimSpace(string(subtree)) != "" {
		return ErrIdentity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		file, err := area.OpenFile("cgroup.procs", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		members, err := io.ReadAll(io.LimitReader(file, 32769))
		err = errors.Join(err, file.Close())
		if err != nil || len(members) > 32768 {
			return ErrIdentity
		}
		if routedCgroupOnlySupervisorV3(members, os.Getpid()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-time.After(20 * time.Millisecond):
		}
	}
}
