//go:build linux

package configpoc

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// Explicitly modeled readback: these tests verify journal/persistence rules,
// not actual listener or kernel absence. Runtime supplies the real adapter.
type inactiveSourceAbsenceFixtureV3 struct {
	hash     string
	calls    int
	failAt   int
	applyErr bool
	onApply  func()
}

func (e *inactiveSourceAbsenceFixtureV3) Name() string { return "modeled-inactive-source" }
func (e *inactiveSourceAbsenceFixtureV3) Validate(c Config) error {
	r, err := Canonical(c)
	if err != nil || r.Config.SchemaVersion != 3 || len(r.Config.LocalServices.Services) != 0 {
		return ErrInvalid
	}
	return nil
}
func (e *inactiveSourceAbsenceFixtureV3) Apply(_ context.Context, r Revision) error {
	if e.applyErr {
		return errors.New("absence not verified")
	}
	if e.onApply != nil {
		e.onApply()
	}
	e.hash = r.Hash
	return nil
}
func (e *inactiveSourceAbsenceFixtureV3) Current() string {
	e.calls++
	if e.calls == e.failAt {
		return ""
	}
	return e.hash
}

func TestInactiveLocalSourceV3ExactlyOneRealInitializeRecord(t *testing.T) {
	area, _ := checkpointFixtureArea(t)
	engine := &inactiveSourceAbsenceFixtureV3{}
	before := time.Now().UTC()
	revision, created, err := PrepareInactiveLocalSourceV3(context.Background(), area, engine)
	if err != nil || created.Before(before) || created.After(time.Now().UTC()) || engine.calls != 3 {
		t.Fatal(revision, created, err, engine.calls)
	}
	fp, err := InspectLegacyV2(area, "local_services")
	if err != nil || fp.Sequence != 1 || fp.Projection != 1 {
		t.Fatal(fp, err)
	}
	image, err := inspectLegacyV2(area, "local_services", nil)
	if err != nil || image.Snapshot.Running.Hash != revision.Hash {
		t.Fatal(err)
	}
	if _, _, err = PrepareInactiveLocalSourceV3(context.Background(), area, &inactiveSourceAbsenceFixtureV3{}); err == nil {
		t.Fatal("existing domain was reset")
	}
	if after, e := InspectLegacyV2(area, "local_services"); e != nil || after != fp {
		t.Fatal("existing source changed", e)
	}
}
func TestInactiveLocalSourceV3FailedAbsenceDoesNotCreateClaim(t *testing.T) {
	for _, engine := range []*inactiveSourceAbsenceFixtureV3{{applyErr: true}, {failAt: 1}, {failAt: 2}, {failAt: 3}} {
		area, _ := checkpointFixtureArea(t)
		_, created, err := PrepareInactiveLocalSourceV3(context.Background(), area, engine)
		if err == nil || !created.IsZero() {
			t.Fatal("failed proof produced success", err, created)
		}
		if engine.failAt == 3 {
			// A failure after durable creation preserves the single record as evidence;
			// it is not an ACK or permission to activate the new runtime.
			fp, e := InspectLegacyV2(area, "local_services")
			if e != nil || fp.Sequence != 1 {
				t.Fatal("partial evidence erased", fp, e)
			}
		} else if _, e := area.Stat("00000001.json"); !os.IsNotExist(e) {
			t.Fatal("record preceded proof", e)
		}
	}
	area, _ := checkpointFixtureArea(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := PrepareInactiveLocalSourceV3(ctx, area, &inactiveSourceAbsenceFixtureV3{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestInactiveLocalSourceV3PinnedRootRejectsPathReplacement(t *testing.T) {
	for _, point := range []string{"apply", "after_stage_sync", "after_record_destination_check", "after_rename"} {
		t.Run(point, func(t *testing.T) {
			area, path := checkpointFixtureArea(t)
			moved := path + "-retained"
			swapped := false
			swap := func() {
				if swapped {
					return
				}
				swapped = true
				if err := os.Rename(path, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(moved) })
			}
			engine := &inactiveSourceAbsenceFixtureV3{}
			if point == "apply" {
				engine.onApply = swap
			}
			hook := func(at string) error {
				if at == point {
					swap()
				}
				return nil
			}
			revision, created, err := prepareInactiveLocalSourceV3(context.Background(), area, engine, hook)
			if !swapped || err == nil || !created.IsZero() || revision.Hash != "" {
				t.Fatal("replaced scope acknowledged", err, created, revision.Hash)
			}
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 0 {
				t.Fatal("replacement directory was written", entries, err)
			}
			if point == "apply" {
				original, openErr := area.Open(".")
				if openErr != nil {
					t.Fatal(openErr)
				}
				entries, err = original.ReadDir(1)
				_ = original.Close()
				if (err != nil && err != io.EOF) || len(entries) != 0 {
					t.Fatal("proof failure wrote original", entries, err)
				}
			}
		})
	}
}
