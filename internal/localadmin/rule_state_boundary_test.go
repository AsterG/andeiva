package localadmin

import (
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/configpoc"
	"testing"
)

func TestForwardingRuleStateSchemaCannotEnterLocalServiceRoute(t *testing.T) {
	f := newFixture(t)
	r := f.request(configpoc.OpStage)
	c := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	r.Transaction.Config = &c
	before := f.m.counts()
	if _, err := f.s.Execute(context.Background(), actor(), r); !errors.Is(err, configpoc.ErrInvalid) {
		t.Fatal("forward-only envelope admitted", err)
	}
	if before != f.m.counts() {
		t.Fatal("domain rejection reached helper")
	}
}
