//go:build linux

package main

import (
	"github.com/AsterG/andeiva/internal/dhcpclient"
	"os"
)

func main() {
	if len(os.Args) != 1 || dhcpclient.WriteHook(os.Stdout) != nil {
		os.Exit(1)
	}
}
