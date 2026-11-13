//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These doubles test predicate ordering and refusal, not kernel deactivation,
// authenticated selected history or actual process drainage. Those are native.
func scopeDrainChecksFixtureV3(calls map[string]int, fail string, nth int) scopeRecoveryDrainChecksV3 {
	check := func(name string) error {
		calls[name]++
		if name == fail && calls[name] == nth {
			return ErrUnavailable
		}
		return nil
	}
	return scopeRecoveryDrainChecksV3{
		selected: func() error { return check("selected") },
		anchors:  func() error { return check("anchors") },
		unit: func() (scopeRecoveryUnitV3, error) {
			return scopeRecoveryUnitV3{mainPID: 77, invocation: strings.Repeat("b", 32)}, check("unit")
		},
		current: func() (RoutedScopeRecoveryFileV3, error) { return RoutedScopeRecoveryFileV3{2, 11}, check("current") },
		events: func() ([]byte, error) {
			if err := check("events"); err != nil {
				return nil, err
			}
			return nil, unix.ENODEV
		},
		oldLive:     func(bool) error { return check("oldLive") },
		currentLive: func() error { return check("currentLive") },
		drained:     func() error { return check("drained") },
	}
}

func TestRoutedScopeRecoveryV3DeactivatedRequiresCompletePredicate(t *testing.T) {
	old := RoutedScopeRecoveryFileV3{2, 10}
	invocation := strings.Repeat("a", 32)
	calls := map[string]int{}
	if err := verifyScopeRecoveryDrainV3(context.Background(), old, invocation, scopeDrainChecksFixtureV3(calls, "", 0)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"selected", "anchors", "unit", "current", "events", "currentLive", "drained"} {
		if calls[name] != 2 {
			t.Fatal("missing repeat of authority/drain", name, calls)
		}
	}
	if calls["oldLive"] != 0 {
		t.Fatal("reopened removed cgroup controls")
	}
	for _, name := range []string{"selected", "anchors", "unit", "current", "events", "currentLive", "drained"} {
		for _, nth := range []int{1, 2} {
			t.Run(name+string(rune('0'+nth)), func(t *testing.T) {
				calls := map[string]int{}
				c := scopeDrainChecksFixtureV3(calls, name, nth)
				if err := verifyScopeRecoveryDrainV3(context.Background(), old, invocation, c); err == nil {
					t.Fatal("uncertain predicate authorized retirement", name, nth, calls)
				}
				if calls[name] != nth {
					t.Fatal("failure gate skipped", calls)
				}
				if name == "selected" && nth == 1 && calls["events"] != 0 {
					t.Fatal("ENODEV inspected before selected proof")
				}
			})
		}
	}
}

func TestRoutedScopeRecoveryV3DeactivationChangesRefused(t *testing.T) {
	old := RoutedScopeRecoveryFileV3{2, 10}
	a := strings.Repeat("a", 32)
	for _, change := range []string{"same_inode", "same_invocation", "foreign_device", "new_invocation", "new_pid", "replacement_group", "live_again", "bytes_with_errno", "ENOENT", "EACCES", "EIO", "cancel", "missing_selected"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := map[string]int{}
			c := scopeDrainChecksFixtureV3(calls, "", 0)
			switch change {
			case "same_inode":
				c.current = func() (RoutedScopeRecoveryFileV3, error) { return old, nil }
			case "foreign_device":
				c.current = func() (RoutedScopeRecoveryFileV3, error) { return RoutedScopeRecoveryFileV3{3, 11}, nil }
			case "same_invocation":
				c.unit = func() (scopeRecoveryUnitV3, error) { return scopeRecoveryUnitV3{mainPID: 77, invocation: a}, nil }
			case "new_invocation", "new_pid":
				base := c.unit
				c.unit = func() (scopeRecoveryUnitV3, error) {
					u, e := base()
					if calls["unit"] == 2 {
						if change == "new_invocation" {
							u.invocation = strings.Repeat("c", 32)
						} else {
							u.mainPID++
						}
					}
					return u, e
				}
			case "replacement_group":
				base := c.current
				c.current = func() (RoutedScopeRecoveryFileV3, error) {
					id, e := base()
					if calls["current"] == 2 {
						id.Inode++
					}
					return id, e
				}
			case "live_again":
				base := c.events
				c.events = func() ([]byte, error) {
					raw, e := base()
					if calls["events"] == 2 {
						return []byte("populated 0\nfrozen 0\n"), nil
					}
					return raw, e
				}
			case "bytes_with_errno":
				c.events = func() ([]byte, error) { return []byte("populated 0\nfrozen 0\n"), unix.ENODEV }
			case "ENOENT":
				c.events = func() ([]byte, error) { return nil, unix.ENOENT }
			case "EACCES":
				c.events = func() ([]byte, error) { return nil, unix.EACCES }
			case "EIO":
				c.events = func() ([]byte, error) { return nil, unix.EIO }
			case "cancel":
				c.drained = func() error { cancel(); return nil }
			case "missing_selected":
				c.selected = nil
			}
			if verifyScopeRecoveryDrainV3(ctx, old, a, c) == nil {
				t.Fatal("changed/uncertain deactivation accepted")
			}
		})
	}
}

func TestRoutedScopeRecoveryV3LivePredicatePreserved(t *testing.T) {
	old := RoutedScopeRecoveryFileV3{2, 10}
	a := strings.Repeat("a", 32)
	for _, same := range []bool{false, true} {
		calls := map[string]int{}
		c := scopeDrainChecksFixtureV3(calls, "", 0)
		value := "0"
		if same {
			value = "1"
			c.current = func() (RoutedScopeRecoveryFileV3, error) { return old, nil }
		}
		c.events = func() ([]byte, error) { return []byte("populated " + value + "\nfrozen 0\n"), nil }
		c.oldLive = func(allowSelf bool) error {
			calls["oldLive"]++
			if allowSelf != same {
				t.Fatal("live ownership changed")
			}
			return nil
		}
		if err := verifyScopeRecoveryDrainV3(context.Background(), old, a, c); err != nil {
			t.Fatal(err)
		}
		if calls["oldLive"] != 2 {
			t.Fatal("live controls not revalidated")
		}
		c.oldLive = func(bool) error { return ErrUnavailable }
		if err := verifyScopeRecoveryDrainV3(context.Background(), old, a, c); !errors.Is(err, ErrUnavailable) {
			t.Fatal("live descendants not rejected", err)
		}
	}
}

func TestRoutedScopeRecoveryV3RuntimeIdentityStaysInOriginalBootHost(t *testing.T) {
	m := Metadata{SchemaVersion: 2, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 21, GatewayNamespace: 22}
	if scopeRecoveryRuntimeIdentityV3(m, []byte(m.BootID+"\n"), 21, 21) != nil {
		t.Fatal("exact runtime refused")
	}
	for _, tc := range []struct {
		boot            string
		process, thread uint64
	}{{"", 21, 21}, {"12345678-1234-1234-1234-123456789abd", 21, 21}, {m.BootID, 22, 21}, {m.BootID, 21, 22}, {m.BootID, 0, 21}} {
		if scopeRecoveryRuntimeIdentityV3(m, []byte(tc.boot), tc.process, tc.thread) == nil {
			t.Fatal("new boot or foreign namespace accepted")
		}
	}
	if err := (&RoutedScopeRecoveryV3{}).checkDrainedV3(context.Background(), nil); err == nil {
		t.Fatal("missing selected authority accepted")
	}
}
