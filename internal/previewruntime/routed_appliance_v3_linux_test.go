//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"testing/fstest"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func applianceConfigFixtureV3() Config {
	return Config{SchemaVersion: 1, ListenAddress: "192.0.2.1:9443", Interface: "lan0", AllowedCIDR: "192.0.2.0/24", APIUser: "andeiva-api", HelperUser: "andeiva-helper", IPCGroup: "andeiva-ipc"}
}

func TestRoutedApplianceV3RejectsUntrustedResourcesBeforeIO(t *testing.T) {
	if _, err := NewRoutedApplianceFactoriesV3(Config{}); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	factories, err := NewRoutedApplianceFactoriesV3(applianceConfigFixtureV3())
	if err != nil {
		t.Fatal(err)
	}
	for _, launch := range []RoutedLaunchContextV3{{}, {Integrity: true}, {Integrity: true, StoreBudget: configpoc.BudgetV2{Bytes: 1 << 30, Inodes: 8192}}} {
		out, cleanup, err := factories.API(context.Background(), launch)
		if !errors.Is(err, ErrIdentity) || cleanup != nil || out.Store != nil {
			t.Fatal("untrusted launch opened appliance resources", err)
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-listener")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if validateRoutedManagementV3(file, applianceConfigFixtureV3()) == nil {
		t.Fatal("ordinary file accepted as HTTPS socket")
	}
	if _, err := factories.Helper(context.Background(), RoutedLaunchContextV3{}); !errors.Is(err, ErrIdentity) {
		t.Fatal("untrusted helper accepted", err)
	}
	if err := RunRoutedApplianceRoleV3(context.Background(), "arbitrary"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("arbitrary child role accepted", err)
	}
}

func TestRoutedApplianceV3BoundedOwnedBindings(t *testing.T) {
	mac1 := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	mac2 := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	links := []net.Interface{{Name: "wan0", HardwareAddr: mac1, Flags: net.FlagUp}, {Name: "lan0", HardwareAddr: mac2, Flags: net.FlagUp}, {Name: "lo", Flags: net.FlagLoopback | net.FlagUp}}
	bindings, err := routedApplianceBindingsFromV3(links)
	if err != nil || len(bindings) != 2 || bindings[0].Name != "lan0" || bindings[1].Name != "wan0" {
		t.Fatal(bindings, err)
	}
	for _, mutate := range []func([]net.Interface) []net.Interface{
		func(v []net.Interface) []net.Interface { return v[:1] },
		func(v []net.Interface) []net.Interface { return append(v, net.Interface{Name: "extra"}) },
		func(v []net.Interface) []net.Interface { v[0].Flags = 0; return v },
		func(v []net.Interface) []net.Interface { v[0].HardwareAddr = nil; return v },
		func(v []net.Interface) []net.Interface { v[0].Name = v[1].Name; return v },
		func(v []net.Interface) []net.Interface { v[0].HardwareAddr = v[1].HardwareAddr; return v },
	} {
		copy := append([]net.Interface(nil), links...)
		if _, err := routedApplianceBindingsFromV3(mutate(copy)); err == nil {
			t.Fatal("invalid interface inventory accepted")
		}
	}
}

func TestRoutedApplianceV3StaticAlias(t *testing.T) {
	handler := routedApplianceStaticV3(fstest.MapFS{"index.html": {Data: []byte("ANDEIVA")}})
	for _, path := range []string{"/", "/firewall", "/firewall/"} {
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, httptest.NewRequest(http.MethodGet, path, nil))
		if out.Code != 200 {
			t.Fatal(path, out.Code)
		}
	}
}
