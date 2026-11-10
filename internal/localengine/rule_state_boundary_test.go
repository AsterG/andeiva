package localengine

import (
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/configpoc"
	"testing"
)

func TestForwardOnlySchemaRejectedBeforeLocalEffects(t *testing.T) {
	e, k, l, _ := setup(t)
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.Validate(r.Config), ErrState) || !errors.Is(e.Apply(context.Background(), r), ErrState) {
		t.Fatal("forward-only schema admitted")
	}
	if k.calls != 0 || k.data != nil || len(l.actual) != 0 {
		t.Fatal("rejection caused local effects")
	}
}
