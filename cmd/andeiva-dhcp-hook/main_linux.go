//go:build linux

package main

import (
	"os"

	"github.com/AsterG/andeiva/internal/dhcpclient"
)

func main() {
	if len(os.Args) != 1 || dhcpclient.WriteHook(os.Stdout) != nil {
		os.Exit(1)
	}
}
