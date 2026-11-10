package main

import (
	"os"

	"github.com/AsterG/andeiva/internal/cli"
)

func main() {
	os.Exit(cli.RunInput(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
