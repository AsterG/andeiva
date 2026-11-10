package main

import (
	"fmt"
	"os"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "ANDEIVA_PREVIEW_UNAVAILABLE")
		os.Exit(1)
	}
}
