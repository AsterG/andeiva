package main

import (
	"errors"
	"testing"
)

func TestRunRejectsExecutablesOutsideFixedAllowlist(t *testing.T) {
	for _, path := range []string{"/bin/sh", "dpkg", "/usr/bin/dpkg-extra", "/tmp/usr/bin/dpkg", ""} {
		t.Run(path, func(t *testing.T) {
			data, err := run(path, "--version")
			if !errors.Is(err, errProfile) || data != nil {
				t.Fatal("unlisted executable reached command execution", err)
			}
		})
	}
}
