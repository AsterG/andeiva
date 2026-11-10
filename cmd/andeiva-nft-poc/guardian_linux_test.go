package main

import (
	"strings"
	"testing"
)

func TestHelperRequiresOnlyNetworkAdminCapability(t *testing.T) {
	status := "CapInh:\t0000000000001000\nCapPrm:\t0000000000001000\nCapEff:\t0000000000001000\nCapBnd:\t0000000000001000\nCapAmb:\t0000000000001000\nNoNewPrivs:\t1\n"
	if _, err := helperPrivileges(status); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Replace(status, "CapEff:\t0000000000001000", "CapEff:\t0000000000201000", 1), strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)} {
		if _, err := helperPrivileges(bad); err == nil {
			t.Fatal("accepted unexpected privileges")
		}
	}
}
