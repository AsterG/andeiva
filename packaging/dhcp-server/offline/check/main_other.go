//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stderr, "ANDEIVA_DHCP_OFFLINE_LINUX_REQUIRED"); os.Exit(1) }
