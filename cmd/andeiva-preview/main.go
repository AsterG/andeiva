package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

type roleExit int

func (e roleExit) Error() string { return fmt.Sprintf("ANDEIVA_FIXTURE_EXIT_%d", e) }

func main() {
	if code := finish(run(os.Args[1:]), os.Stderr); code != 0 {
		os.Exit(code)
	}
}

func finish(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var role roleExit
	if errors.As(err, &role) {
		return int(role)
	}
	fmt.Fprintln(stderr, "ANDEIVA_PREVIEW_UNAVAILABLE")
	return 1
}
