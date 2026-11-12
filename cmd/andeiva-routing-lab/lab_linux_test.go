//go:build linux

package main

import "testing"

func TestExecutableAllowlist(t *testing.T) {
	self := "/trusted/andeiva-routing-lab"
	for _, path := range []string{ipPath, nftPath, "/usr/sbin/sysctl", self} {
		if !allowedExecutable(path, self) {
			t.Fatalf("fixed executable rejected: %s", path)
		}
	}
	for _, path := range []string{"", "/bin/sh", "/usr/bin/nft", "/trusted/../trusted/andeiva-routing-lab", "nft", "/usr/sbin/nft;sh", "/trusted/andeiva-routing-lab-extra"} {
		if allowedExecutable(path, self) {
			t.Fatalf("unexpected executable allowed: %s", path)
		}
	}
	if allowedExecutable("", "") {
		t.Fatal("empty self authorizes an executable")
	}
}
