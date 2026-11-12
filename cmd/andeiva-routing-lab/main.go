// andeiva-routing-lab emits the fixed isolated laboratory policy by default.
package main

import (
	"fmt"
	"github.com/AsterG/andeiva/internal/routednft"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		if err := run(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	artifact, e := routednft.Compile(routednft.LabPolicy())
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println(string(artifact.Create))
}
