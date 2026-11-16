package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func execPolicy(t *testing.T, args []string) int {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy")
	if e := os.WriteFile(p, []byte(guard), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("/bin/sh", append([]string{p}, args...)...)
	e := cmd.Run()
	if e == nil {
		return 0
	}
	if x, ok := e.(*exec.ExitError); ok {
		return x.ExitCode()
	}
	t.Fatal(e)
	return -1
}
