// Command secdocs scaffolds, lints and renders security documentation sets.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if !errors.Is(err, errFindings) {
			fmt.Fprintln(os.Stderr, "secdocs:", err)
		}
		os.Exit(exitCode(err))
	}
}
