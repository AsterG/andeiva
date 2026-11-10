// Command andeiva-nft-poc runs an isolated, explicitly authorized Debian laboratory experiment.
package main

import (
	"errors"
	"fmt"
	"os"
)

type exitCode int

func (e exitCode) Error() string { return "ANDEIVA_NFT_FIXTURE_EXIT" }

func main() {
	if err := run(os.Args[1:]); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
