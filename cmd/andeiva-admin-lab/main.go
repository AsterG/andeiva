// Command andeiva-admin-lab hosts an explicitly authorized isolated laboratory.
package main

import (
	"errors"
	"fmt"
	"os"
)

type roleExit int

func (e roleExit) Error() string { return fmt.Sprintf("ANDEIVA_FIXTURE_EXIT_%d", e) }

func main() {
	if err := run(os.Args[1:]); err != nil {
		var exit roleExit
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
