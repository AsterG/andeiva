//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func openTestReserveAreasV2(t *testing.T, areas []*os.Root) *v2ReserveManager {
	t.Helper()
	pools := []*recoveryreserve.PoolV2{}
	for _, area := range areas {
		p, err := recoveryreserve.OpenV2(area)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		pools = append(pools, p)
	}
	m, err := newReserveManagerV2(pools[0], pools[1], pools[2])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReserveCoordinatorProcessExitDuringRetirement(t *testing.T) {
	c, area, _, p, _ := coordinatorV2Fixture(t, false)
	m, areas := attachReserveAreasV2(t, c)
	c.store.hook = func(point string) error {
		if point == "reserve_archive_anchored" {
			return ErrInterrupted
		}
		return nil
	}
	config := coordinatorV2Rule("process-exit")
	op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	c.close()
	_ = c.store.close()
	for _, pool := range []*recoveryreserve.PoolV2{m.admission, m.plan, m.emergency} {
		if err = pool.Close(); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestReserveCoordinatorProcessExitHelper$")
	cmd.Env = append(os.Environ(), "ANDEIVA_RESERVE_EXIT_STORE="+area.Name(), "ANDEIVA_RESERVE_EXIT_ADMISSION="+areas[0].Name(), "ANDEIVA_RESERVE_EXIT_PLAN="+areas[1].Name(), "ANDEIVA_RESERVE_EXIT_EMERGENCY="+areas[2].Name())
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 47 {
		t.Fatalf("expected abrupt process exit47: %v %s", err, output)
	}
	s, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	s.reserves = openTestReserveAreasV2(t, areas)
	if err = s.reserves.verifySelected(s); err != nil {
		t.Fatal("selected archive did not replace retired binding", err)
	}
	if err = s.reserves.maintain(s); err != nil {
		t.Fatal("retirement cannot resume after process exit", err)
	}
	final, err := s.lookup(p.Subject, op.ID)
	if err != nil || final.State != "final" || len(s.state.ActiveReserves) != 0 || s.state.ReservedBytes != 0 {
		t.Fatal("process lost canonical finality", err)
	}
}

func TestReserveCoordinatorProcessExitHelper(t *testing.T) {
	path := os.Getenv("ANDEIVA_RESERVE_EXIT_STORE")
	if path == "" {
		return
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	areas := []*os.Root{}
	for _, name := range []string{"ANDEIVA_RESERVE_EXIT_ADMISSION", "ANDEIVA_RESERVE_EXIT_PLAN", "ANDEIVA_RESERVE_EXIT_EMERGENCY"} {
		a, e := os.OpenRoot(os.Getenv(name))
		if e != nil {
			t.Fatal(e)
		}
		defer a.Close()
		areas = append(areas, a)
	}
	s, err := openV2(area, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.reserves = openTestReserveAreasV2(t, areas)
	if os.Getenv("ANDEIVA_RESERVE_EXIT_STAGING") == "1" {
		s.hook = func(point string) error {
			if point == "after_reserve_staging_quarantine" {
				os.Exit(47)
			}
			return nil
		}
		if err = recoverReservePendingV2(s, s.reserves); err != nil {
			t.Fatal(err)
		}
		t.Fatal("staging crash point was not reached")
	}
	s.hook = func(point string) error {
		if point == "reserve_role_retired" {
			os.Exit(47)
		}
		return nil
	}
	if err = s.reserves.maintain(s); err != nil {
		t.Fatal(err)
	}
	t.Fatal("fault point was never reached")
}

func TestReserveCoordinatorProcessExitAfterStagingQuarantine(t *testing.T) {
	c, area, _, _, _ := coordinatorV2Fixture(t, false)
	m, areas := attachReserveAreasV2(t, c)
	data := reservePendingFixtureV2(t, c.store)
	selected := c.store.selector
	c.close()
	_ = c.store.close()
	for _, pool := range []*recoveryreserve.PoolV2{m.admission, m.plan, m.emergency} {
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestReserveCoordinatorProcessExitHelper$")
	cmd.Env = append(os.Environ(), "ANDEIVA_RESERVE_EXIT_STAGING=1", "ANDEIVA_RESERVE_EXIT_STORE="+area.Name(), "ANDEIVA_RESERVE_EXIT_ADMISSION="+areas[0].Name(), "ANDEIVA_RESERVE_EXIT_PLAN="+areas[1].Name(), "ANDEIVA_RESERVE_EXIT_EMERGENCY="+areas[2].Name())
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 47 {
		t.Fatalf("expected abrupt staging exit47: %v %s", err, output)
	}
	s, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.blocked || s.selector != selected {
		t.Fatal("quarantine crash adopted staged state")
	}
	name, _ := v2ObjectName(checkpointDigest(data))
	actual, err := checkpointRead(area, name, 4096)
	if err != nil || string(actual) != string(data) {
		t.Fatal("process exit lost staging evidence", err)
	}
}
