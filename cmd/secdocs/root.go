package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// errFindings is returned when lint findings reach the failure threshold.
// It exits with status 1, like other errors, but prints nothing extra.
var errFindings = errors.New("lint findings at or above the failure threshold")

func exitCode(err error) int {
	if errors.Is(err, errFindings) {
		return 1
	}
	return 2
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "secdocs",
		Short: "Scaffold, lint and render security documentation from a typed JSON spec",
		Long: `secdocs works on a security documentation set: one JSON file per product
holding shared facts (hosting, encryption, backups, deletion windows, ...)
and typed documents (security overview, security response, subprocessors,
data handling, incident response, availability).

  secdocs init      write a starter set where every claim is "todo"
  secdocs lint      report what is invalid or still to be done
  secdocs render    write Markdown for an audience (public, nda, internal)
  secdocs export    write the same audience's view as JSON
  secdocs security-txt  write an RFC 9116 security.txt
  secdocs schema    print the JSON Schema`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newInitCmd(), newLintCmd(), newRenderCmd(), newExportCmd(), newSecurityTxtCmd(), newSchemaCmd())
	return root
}
