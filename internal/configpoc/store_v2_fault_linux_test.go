//go:build linux

package configpoc

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestV2PublicationFaultsPreserveCompleteSelection(t *testing.T) {
	for _, point := range []string{"object_written", "object_synced", "objects_durable", "before_select", "after_select"} {
		t.Run(point, func(t *testing.T) {
			s, area, now, subject := v2Fixture(t, 64)
			ns, err := s.namespace(subject, "firewall", now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			old := s.selector.Current
			s.hook = func(at string) error {
				if at == point {
					return errors.New("injected interruption")
				}
				return nil
			}
			if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now); err == nil {
				t.Fatal("fault succeeded")
			}
			if !s.blocked {
				t.Fatal("ambiguous writer not fenced")
			}
			_ = s.close()
			reopened, e := openV2(area, s.budget)
			if e != nil {
				t.Fatal("previous complete pair not readable", e)
			}
			defer reopened.close()
			if point == "after_select" {
				if reopened.state.HighWater != 1 {
					t.Fatal("selected result lost")
				}
			} else if reopened.selector.Current != old {
				t.Fatal("partial selection published")
			}
			if point == "before_select" && !reopened.blocked {
				t.Fatal("unowned pending selector accepted for overwrite")
			}
		})
	}
}

func TestV2StrictFormatAndTamper(t *testing.T) {
	for _, kind := range []string{"duplicate", "unknown", "trailing", "version", "state", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			selected, err := checkpointRead(area, "selected.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.close()
			switch kind {
			case "duplicate":
				selected = bytes.Replace(selected, []byte(`{"format":`), []byte(`{"format":"ignored","format":`), 1)
			case "unknown":
				selected = bytes.Replace(selected, []byte(`{"format":`), []byte(`{"unexpected":0,"format":`), 1)
			case "trailing":
				selected = append(selected, []byte(" {}")...)
			case "version":
				selected = bytes.ReplaceAll(selected, []byte(v2Format), []byte("andeiva.configuration.store.v99"))
			case "state":
				name, _ := v2ObjectName(s.selection.State)
				if err = area.WriteFile(name, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = area.Remove("selected.json"); err != nil {
					t.Fatal(err)
				}
				if err = area.Symlink("foreign", "selected.json"); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "state" && kind != "symlink" {
				if err = area.WriteFile("selected.json", selected, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, e := openV2(area, s.budget); e == nil {
				_ = reopened.close()
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestV2ProcessExitSelection(t *testing.T) {
	if os.Getenv("ANDEIVA_V2_TEST_CHILD") == "yes" {
		area, err := os.OpenRoot(os.Getenv("ANDEIVA_V2_TEST_DIR"))
		if err != nil {
			os.Exit(75)
		}
		s, err := openV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000})
		if err != nil {
			os.Exit(76)
		}
		s.hook = func(at string) error {
			if at == os.Getenv("ANDEIVA_V2_TEST_POINT") {
				os.Exit(74)
			}
			return nil
		}
		_, _ = s.namespace(s.state.Subjects[0].ID, "firewall", s.state.Clock, time.Hour)
		os.Exit(77)
	}
	for _, point := range []string{"object_written", "objects_durable", "before_select", "after_select"} {
		t.Run(point, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			_ = s.close()
			command := exec.Command(os.Args[0], "-test.run=^TestV2ProcessExitSelection$")
			command.Env = append(os.Environ(), "ANDEIVA_V2_TEST_CHILD=yes", "ANDEIVA_V2_TEST_DIR="+area.Name(), "ANDEIVA_V2_TEST_POINT="+point)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("child %v %s", err, output)
			}
			reopened, err := openV2(area, s.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close()
			if point == "after_select" && len(reopened.state.Namespaces) != 1 {
				t.Fatal("selected namespace lost")
			}
			if point != "after_select" && len(reopened.state.Namespaces) != 0 {
				t.Fatal("partial namespace selected")
			}
		})
	}
}
