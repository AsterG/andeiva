//go:build linux

package previewruntime

import (
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedEmptyListenersV3RejectUnboundAndForeignState(t *testing.T) {
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, listeners := range []*routedEmptyListenersV3{nil, {}, {kernel: &routedKernelV3{namespace: current, host: current}}} {
		if _, err = listeners.Observe(context.Background()); err == nil {
			t.Fatal("unbound namespace published socket absence")
		}
		if err = listeners.Apply(context.Background(), configpoc.Revision{}); err == nil {
			t.Fatal("invalid revision accepted")
		}
	}
	if listeners, err := newRoutedEmptyListenersV3(Metadata{}); err == nil || listeners != nil {
		t.Fatal("untrusted namespace accepted")
	}
}
