//go:build linux

package configpoc

import (
	"errors"
	"reflect"
	"testing"
)

func TestReserveActivationRejectsOversizedCoreWithoutChangingLegacy(t *testing.T) {
	s, area, _, subject := v2Fixture(t, 64)
	growReserveMetadataFixtureV2(t, s, subject)
	core, _, err := v2Canonical(reserveMetadataCoreV2(s.state))
	if err != nil || len(core) <= 128*1024 {
		t.Fatal("fixture does not exceed migration profile", err)
	}
	before := clone(s.state)
	selector := s.selector
	files := journalFiles(t, area.Name())
	s.mu.Lock()
	err = s.enableClosingCreditsLocked()
	s.mu.Unlock()
	if !errors.Is(err, errV2Limited) || s.blocked || s.selector != selector || !reflect.DeepEqual(s.state, before) || !reflect.DeepEqual(files, journalFiles(t, area.Name())) {
		t.Fatal("incompatible opt-in fenced or mutated legacy state", err)
	}
}
