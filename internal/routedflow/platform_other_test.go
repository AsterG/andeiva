//go:build !linux

package routedflow

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatformHasNoFallback(t *testing.T) {
	s, e := Collect(context.Background())
	if !errors.Is(e, ErrUnsupported) || s.Flows != nil {
		t.Fatal("unsupported platform returned observations", e)
	}
}
