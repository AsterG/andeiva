package configpoc

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

// PrepareInactiveLocalSourceV3 creates exactly one initialize record for a new
// domain. The trusted absence engine must perform actual readback in Apply and
// Current, without creating listeners or rules. It is never supplied by HTTP.
func PrepareInactiveLocalSourceV3(ctx context.Context, area *os.Root, absence Engine) (revision Revision, created time.Time, result error) {
	return prepareInactiveLocalSourceV3(ctx, area, absence, nil)
}

func prepareInactiveLocalSourceV3(ctx context.Context, area *os.Root, absence Engine, hook func(string) error) (revision Revision, created time.Time, result error) {
	if ctx == nil || area == nil || absence == nil {
		return revision, created, ErrInvalid
	}
	if ctx.Err() != nil {
		return revision, created, ctx.Err()
	}
	info, err := area.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return revision, created, ErrStorage
	}
	named, nameErr := os.Lstat(area.Name())
	if nameErr != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, named) {
		return revision, created, ErrStorage
	}
	directory, err := area.Open(".")
	if err != nil {
		return revision, created, err
	}
	entries, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) != 0 {
		return revision, created, ErrStorage
	}
	revision, err = Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", Rules: []Rule{}, LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}})
	if err != nil {
		return Revision{}, time.Time{}, err
	}
	if absence.Validate(clone(revision.Config)) != nil || ctx.Err() != nil {
		return Revision{}, time.Time{}, ErrEngine
	}
	if absence.Apply(ctx, clone(revision)) != nil || ctx.Err() != nil || absence.Current() != revision.Hash || ctx.Err() != nil {
		return Revision{}, time.Time{}, ErrEngine
	}
	store, err := openInactiveLocalSourceV3(area)
	if err != nil {
		return Revision{}, time.Time{}, err
	}
	defer func() {
		result = errors.Join(result, store.lock.Close())
		if result != nil {
			revision = Revision{}
			created = time.Time{}
		}
	}()
	if len(store.records) != 0 {
		return Revision{}, time.Time{}, ErrStorage
	}
	// Recheck after acquiring the actual source writer lock, before any record.
	if absence.Current() != revision.Hash || ctx.Err() != nil {
		return Revision{}, time.Time{}, ErrEngine
	}
	created = time.Now().UTC()
	state := durableState{Snapshot: Snapshot{Generation: 1, Running: revision, Startup: revision, LastGood: revision, Revoked: []string{}}, Receipts: map[string]receipt{}}
	if err = store.append(state, Audit{Sequence: 1, At: created, Actor: "system", Surface: API, Operation: "initialize", Result: "ok", RunningHash: revision.Hash}, true, hook); err != nil {
		return Revision{}, time.Time{}, err
	}
	if absence.Current() != revision.Hash || ctx.Err() != nil {
		return Revision{}, time.Time{}, ErrRecovery
	}
	actual, nameErr := os.Lstat(area.Name())
	pinned, pinErr := area.Stat(".")
	if nameErr != nil || pinErr != nil || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(actual, pinned) {
		return Revision{}, time.Time{}, ErrRecovery
	}
	return revision, created, nil
}
