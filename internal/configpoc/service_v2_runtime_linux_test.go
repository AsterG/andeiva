//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeServiceV2SelectedPoolsAndCurrent(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	m := attachReserveManagerV2(t, c)
	subject := c.store.state.Subjects[0]
	auth, binding, _ := serviceV2Auth(t, p.Subject, subject.Login, "admin", subject.CredentialRevision)
	budget := BudgetV2{Bytes: c.store.budget.Bytes, Inodes: c.store.budget.Inodes}
	options := RuntimeOptionsV2{Pools: RuntimePoolsV2{Admission: m.admission, Plan: m.plan, Emergency: m.emergency}, GuardDeadlines: true}
	if _, err := OpenRuntimeServiceV2(context.Background(), area, budget, auth, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, RuntimeOptionsV2{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing resources attempted to open store", err)
	}
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	service, err := OpenRuntimeServiceV2(context.Background(), area, budget, auth, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if !service.AuthenticatedBy(auth) || service.coordinator.store.reserves == nil || !service.coordinator.options.GuardDeadlines {
		t.Fatal("runtime resources not selected")
	}
	current, err := service.Current(binding, "firewall")
	if err != nil || current.Global.Generation == 0 || current.Global.Lineage == "" || current.Snapshot.Running.Hash == "" {
		t.Fatal("current", err)
	}
	current.Snapshot.Running.Config.DefaultAction = "allow"
	again, err := service.Current(binding, "firewall")
	if err != nil || again.Snapshot.Running.Config.DefaultAction != "deny" {
		t.Fatal("current aliased canonical state", err)
	}
	if _, err := service.Current(binding, "routed"); !errors.Is(err, ErrDenied) {
		t.Fatal("unassembled domain advertised", err)
	}
}
