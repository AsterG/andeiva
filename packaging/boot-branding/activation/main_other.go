//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ANDEIVA_BOOT_REQUIRES_LINUX")
	os.Exit(1)
}
