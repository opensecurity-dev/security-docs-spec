package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/security-docs-spec/lint"
	"github.com/opensecurity-dev/security-docs-spec/spec"
)

func newLintCmd() *cobra.Command {
	var format, failOn, now string
	var strict bool
	cmd := &cobra.Command{
		Use:   "lint FILE...",
		Short: "Report what is invalid or still to be done in document sets",
		Long: `lint reports, per JSON path:

  error    the set is invalid or contradicts itself (a planned claim with no
           gap, an unknown placeholder, an expired certification)
  warning  work left before publishing (todo claims, missing dates, stale
           reviews, leftover TODO markers)
  info     advice (no response target, no safe-harbor statement)

It exits 1 when a finding reaches --fail-on (default error).
Use --fail-on warning as the gate before publishing.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := lint.ParseSeverity(failOn)
			if err != nil {
				return err
			}
			opts := lint.Options{Strict: strict}
			if now != "" {
				if opts.Now, err = time.Parse(time.DateOnly, now); err != nil {
					return fmt.Errorf("--now: %w", err)
				}
			}
			w := cmd.OutOrStdout()
			failed := false
			results := map[string]lint.Report{}
			for _, path := range args {
				set, err := spec.Load(path)
				if err != nil {
					return err
				}
				rep := lint.Run(set, opts)
				results[path] = rep
				if threshold != "" && rep.Max().Rank() >= threshold.Rank() {
					failed = true
				}
				if format == "text" {
					for _, f := range rep.Findings {
						fmt.Fprintf(w, "%s: %s\n", path, f)
					}
					fmt.Fprintf(w, "%s: %d errors, %d warnings, %d info\n", path,
						rep.Counts["error"], rep.Counts["warning"], rep.Counts["info"])
				}
			}
			switch format {
			case "text":
			case "json":
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				if err := enc.Encode(results); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown --format %q; want text or json", format)
			}
			if failed {
				return errFindings
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit 1 at this severity or above: error, warning, info or none")
	cmd.Flags().BoolVar(&strict, "strict", false, "report public claims that are not reviewed or verified as warnings")
	cmd.Flags().StringVar(&now, "now", "", "date (YYYY-MM-DD) to measure staleness against (default today)")
	return cmd
}
