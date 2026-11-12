//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This persistent test engine models a kernel state surviving controller exit.
// It is a fixture only: no process, host rule, socket or interface is configured.
type persistentCoordinatorV2Engine struct {
	area *os.Root
	name string
}

func (e *persistentCoordinatorV2Engine) Name() string { return e.name }
func (e *persistentCoordinatorV2Engine) Validate(config Config) error {
	_, err := Canonical(config)
	return err
}
func (e *persistentCoordinatorV2Engine) Current() string {
	data, err := e.area.ReadFile(e.name + ".hash")
	if err != nil {
		return ""
	}
	return string(data)
}
func (e *persistentCoordinatorV2Engine) Apply(ctx context.Context, revision Revision) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	file, err := e.area.OpenFile(e.name+".hash", os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write([]byte(revision.Hash))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	log, err := e.area.OpenFile(e.name+".history", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	_, writeErr = log.Write([]byte(revision.Hash + "\n"))
	syncErr = log.Sync()
	closeErr = log.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func persistentCoordinatorV2Engines(area *os.Root) ([]Engine, []Engine) {
	return []Engine{&persistentCoordinatorV2Engine{area, "fw-first"}, &persistentCoordinatorV2Engine{area, "fw-second"}}, []Engine{&persistentCoordinatorV2Engine{area, "local-only"}}
}

func TestCoordinatorV2ProcessExitWithPersistentSimulatedComponents(t *testing.T) {
	if os.Getenv("ANDEIVA_V2_COORDINATOR_CHILD") == "1" {
		area, err := os.OpenRoot(os.Getenv("ANDEIVA_V2_COORDINATOR_STATE"))
		if err != nil {
			os.Exit(75)
		}
		components, err := os.OpenRoot(os.Getenv("ANDEIVA_V2_COORDINATOR_COMPONENTS"))
		if err != nil {
			os.Exit(76)
		}
		store, err := openV2(area, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20})
		if err != nil {
			os.Exit(77)
		}
		firewall, local := persistentCoordinatorV2Engines(components)
		coordinator, err := openCoordinatorV2(context.Background(), store, firewall, local, v2CoordinatorOptions{ManualTimeout: true, Hook: func(point string) error {
			if point == os.Getenv("ANDEIVA_V2_COORDINATOR_POINT") {
				os.Exit(74)
			}
			return nil
		}})
		if err != nil {
			os.Exit(78)
		}
		_, _ = coordinator.execute(context.Background(), v2TrustedPrincipal{Subject: store.state.Subjects[0].ID, Role: RoleAdmin}, os.Getenv("ANDEIVA_V2_COORDINATOR_OPERATION"))
		os.Exit(79)
	}
	for _, point := range []string{"after_intent", "after_component_apply", "after_readback"} {
		t.Run(point, func(t *testing.T) {
			seed, area, _, p, _ := coordinatorV2Fixture(t, false)
			initial, _, _ := seed.status(p)
			components, _ := checkpointFixtureArea(t)
			for _, name := range []string{"fw-first", "fw-second", "local-only"} {
				hash := initial.Firewall.Running.Hash
				if name == "local-only" {
					hash = initial.LocalServices.Running.Hash
				}
				if err := components.WriteFile(name+".hash", []byte(hash), 0600); err != nil {
					t.Fatal(err)
				}
			}
			seed.close()
			firewall, local := persistentCoordinatorV2Engines(components)
			c, err := openCoordinatorV2(context.Background(), seed.store, firewall, local, v2CoordinatorOptions{ManualTimeout: true})
			if err != nil {
				t.Fatal(err)
			}
			staged := coordinatorV2Stage(t, c, p, "process")
			_, generation, _ := c.status(p)
			namespace, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			zero := uint64(0)
			op, err := c.store.admit(p.Subject, namespace.ID, generation, v2Request{Kind: OpCommit, ConfirmSeconds: &zero}, c.now())
			if err != nil {
				t.Fatal(err)
			}
			c.close()
			if err = c.store.close(); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestCoordinatorV2ProcessExitWithPersistentSimulatedComponents$")
			command.Env = append(os.Environ(), "ANDEIVA_V2_COORDINATOR_CHILD=1", "ANDEIVA_V2_COORDINATOR_STATE="+area.Name(), "ANDEIVA_V2_COORDINATOR_COMPONENTS="+components.Name(), "ANDEIVA_V2_COORDINATOR_OPERATION="+op.ID, "ANDEIVA_V2_COORDINATOR_POINT="+point)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("process boundary %v %s", err, output)
			}
			countTarget := func() int {
				total := 0
				for _, name := range []string{"fw-first", "fw-second"} {
					data, e := components.ReadFile(name + ".history")
					if e != nil && !os.IsNotExist(e) {
						t.Fatal(e)
					}
					total += strings.Count(string(data), staged.Current.Firewall.Candidate.Revision.Hash+"\n")
				}
				return total
			}
			before := countTarget()
			store, err := openV2(area, c.store.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			resumed, err := openCoordinatorV2(context.Background(), store, firewall, local, v2CoordinatorOptions{ManualTimeout: true})
			if err != nil {
				t.Fatal("cold recovery", err)
			}
			defer resumed.close()
			if countTarget() != before {
				t.Fatal("restart replayed target effects")
			}
			for _, engine := range firewall {
				if engine.Current() != initial.Firewall.Running.Hash {
					t.Fatal("process interruption lost last-known-good enforcement")
				}
			}
			stored, err := store.lookup(p.Subject, op.ID)
			if err != nil || stored.Outcome == nil || stored.Outcome.Code != "failed_rolled_back" {
				t.Fatal("crash falsely published success", err)
			}
		})
	}
}
