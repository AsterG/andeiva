package dhcpclient

import (
	"errors"
	"strings"
	"testing"
)

func goodEnv() []string {
	return []string{
		"interface=wan0", "reason=BOUND", "protocol=dhcp", "if_configured=false", "pid=123",
		"new_ip_address=198.18.1.10", "new_subnet_cidr=24", "new_routers=198.18.1.1",
		"new_dhcp_server_identifier=198.18.1.1", "new_dhcp_lease_time=120", "new_domain_name_servers=198.18.1.1",
	}
}
func replace(env []string, key, val string) []string {
	for i, s := range env {
		if strings.HasPrefix(s, key+"=") {
			env[i] = key + "=" + val
			return env
		}
	}
	return append(env, key+"="+val)
}
func TestHookBoundedAllowlist(t *testing.T) {
	for _, reason := range []string{"BOUND", "RENEW", "REBIND", "REBOOT"} {
		e, err := HookEvent(replace(goodEnv(), "reason", reason), 100)
		if err != nil || e.Reason != reason || e.Address != "198.18.1.10/24" || e.Seconds != 120 {
			t.Fatal(e, err)
		}
	}
	for _, tc := range [][2]string{
		{"interface", "--config=/etc/evil"}, {"protocol", "dhcp6"}, {"if_configured", "true"},
		{"new_ip_address", "198.18.1.0"}, {"new_ip_address", "198.18.1.255"}, {"new_ip_address", "127.0.0.1"},
		{"new_ip_address", "198.18.1.10;id"}, {"new_subnet_cidr", "024"}, {"new_subnet_cidr", "31"},
		{"new_routers", "198.18.2.1"}, {"new_routers", "198.18.1.255"}, {"new_routers", "198.18.1.1 198.18.1.2"},
		{"new_dhcp_lease_time", "4294967295"}, {"new_dhcp_lease_time", "0"}, {"new_dhcp_lease_time", "0120"},
		{"new_classless_static_routes", "0.0.0.0/0 198.18.1.1"}, {"new_static_routes", "198.19.0.0 198.18.1.2"},
		{"new_ms_classless_static_routes", "evil"}, {"new_domain_name_servers", "198.18.1.1 198.18.1.1"},
		{"new_domain_name_servers", "::1"}, {"pid", "00123"}, {"reason", "STATIC"}, {"reason", "TEST"},
	} {
		t.Run(tc[0]+tc[1], func(t *testing.T) {
			if _, err := HookEvent(replace(goodEnv(), tc[0], tc[1]), 100); !errors.Is(err, ErrEvent) {
				t.Fatal(err)
			}
		})
	}
	if _, err := HookEvent(append(goodEnv(), "pid=123"), 100); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := HookEvent(append(goodEnv(), "unused="+strings.Repeat("x", 64<<10)), 100); err == nil {
		t.Fatal("unbounded environment")
	}
}
func TestHookRevocationNeverCarriesCachedLease(t *testing.T) {
	for _, reason := range []string{"NAK", "EXPIRE", "TIMEOUT", "NOCARRIER", "STOP", "STOPPED", "FAIL"} {
		e, err := HookEvent(replace(goodEnv(), "reason", reason), 100)
		if err != nil || e.Address != "" || e.Seconds != 0 || len(e.DNS) != 0 {
			t.Fatal(e, err)
		}
	}
}
