//go:build linux

package configpoc

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func reservePendingFixtureV2(t *testing.T, s *v2Store) []byte {
	t.Helper()
	st := clone(s.state)
	st.Clock = st.Clock.Add(time.Second)
	hash, err := s.object(st)
	if err != nil {
		t.Fatal(err)
	}
	selection := v2Selection{Format: v2Format, Lineage: st.Lineage, Sequence: s.selection.Sequence + 1, State: hash, Previous: s.selector.Current, Segment: s.selection.Segment + 1}
	if selection.Segment > 64 {
		selection.Segment = 1
		selection.Checkpoint = true
	}
	hash, err = s.object(selection)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := v2Canonical(v2Selector{Format: v2Format, Current: hash, Previous: s.selector.Current})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checkpointWrite(s.root, "selection.pending", data, nil, ""); err != nil {
		t.Fatal(err)
	}
	s.blocked = true
	return data
}

func TestReserveStagingRecoveryPreservesSelectedAndQuarantinesBytes(t *testing.T) {
	c, _, _, _, _ := coordinatorV2Fixture(t, false)
	m := attachReserveManagerV2(t, c)
	data := reservePendingFixtureV2(t, c.store)
	selected := c.store.selector
	if err := recoverReservePendingV2(c.store, m); err != nil {
		t.Fatal(err)
	}
	if c.store.selector != selected || c.store.blocked {
		t.Fatal("unselected state became authority")
	}
	name, _ := v2ObjectName(checkpointDigest(data))
	actual, err := checkpointRead(c.store.root, name, 4096)
	if err != nil || !bytes.Equal(data, actual) {
		t.Fatal("quarantine lost exact evidence", err)
	}
	if _, err = c.store.root.Lstat("selection.pending"); !os.IsNotExist(err) {
		t.Fatal("staging name remains", err)
	}
}

func TestReserveStagingRecoveryRejectsForeignOrAmbiguous(t *testing.T) {
	for _, kind := range []string{"malformed", "permissions", "hardlink", "symlink", "existing-destination", "swap-after-validation", "without-resources"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _, _ := coordinatorV2Fixture(t, false)
			m := attachReserveManagerV2(t, c)
			s := c.store
			data := reservePendingFixtureV2(t, s)
			selected := s.selector
			foreign := []byte("foreign material must survive")
			switch kind {
			case "malformed":
				if err := s.root.WriteFile("selection.pending", foreign, 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				f, err := s.root.OpenFile("selection.pending", os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.Chmod(0644); err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
			case "hardlink":
				if err := s.root.Link("selection.pending", "foreign-link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := s.root.Rename("selection.pending", "foreign-target"); err != nil {
					t.Fatal(err)
				}
				if err := s.root.Symlink("foreign-target", "selection.pending"); err != nil {
					t.Fatal(err)
				}
			case "existing-destination":
				name, _ := v2ObjectName(checkpointDigest(data))
				if err := s.root.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "swap-after-validation":
				s.hook = func(point string) error {
					if point == "before_reserve_staging_quarantine" {
						if err := s.root.Rename("selection.pending", "original-test-staging"); err != nil {
							return err
						}
						return s.root.WriteFile("selection.pending", foreign, 0600)
					}
					return nil
				}
			case "without-resources":
				m = nil
			}
			if err := recoverReservePendingV2(s, m); err == nil || !s.blocked || s.selector != selected {
				t.Fatal("ambiguous staging unblocked or adopted", err)
			}
			if kind == "swap-after-validation" {
				actual, err := checkpointRead(s.root, "selection.pending", 4096)
				if err != nil || !bytes.Equal(actual, foreign) {
					t.Fatal("foreign replacement deleted", err)
				}
			}
			if kind == "existing-destination" {
				name, _ := v2ObjectName(checkpointDigest(data))
				actual, err := checkpointRead(s.root, name, 4096)
				if err != nil || !bytes.Equal(actual, data) {
					t.Fatal("existing quarantine overwritten", err)
				}
			}
		})
	}
}
