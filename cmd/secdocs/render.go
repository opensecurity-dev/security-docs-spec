package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/security-docs-spec/render"
	"github.com/opensecurity-dev/security-docs-spec/spec"
)

func newRenderCmd() *cobra.Command {
	var out, audience, single string
	var only []string
	var opts render.Options
	cmd := &cobra.Command{
		Use:   "render FILE",
		Short: "Write Markdown documents for an audience",
		Long: `render writes one Markdown file per document, plus index.md, into the
output directory. Content whose visibility is wider than --audience is left
out before rendering. Claims still marked todo, and not-applicable ones, are
left out unless --draft is given.

For DOCX or PDF, use --front-matter and Pandoc, for example:

  secdocs render set.json --front-matter --single security.md -o out
  pandoc out/security.md -o security.docx`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := spec.Load(args[0])
			if err != nil {
				return err
			}
			opts.Audience = spec.Visibility(audience)
			opts.Only = only
			if opts.LinkJSON && (single != "" || len(only) > 0) {
				return fmt.Errorf("--json writes the whole set; it cannot be combined with --single or --only")
			}
			files, err := render.Render(set, opts)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(out, 0o750); err != nil {
				return err
			}
			if single != "" {
				view, err := set.ForAudience(opts.Audience)
				if err != nil {
					return err
				}
				return write(cmd, filepath.Join(out, single), render.Combine(view, files, opts.FrontMatter))
			}
			for _, f := range files {
				if err := write(cmd, filepath.Join(out, f.Name), f.Content); err != nil {
					return err
				}
			}
			if opts.LinkJSON {
				b, err := render.ExportJSON(set, opts.Audience, opts.Draft)
				if err != nil {
					return err
				}
				return write(cmd, filepath.Join(out, render.ExportName), string(b))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "out", "output directory")
	cmd.Flags().StringVar(&audience, "audience", "public", "widest visibility to render: public, nda or internal")
	cmd.Flags().BoolVar(&opts.Draft, "draft", false, "include todo and not-applicable claims with visible markers, for review")
	cmd.Flags().BoolVar(&opts.HideGaps, "hide-gaps", false, "leave out gap text of partial and planned claims")
	cmd.Flags().BoolVar(&opts.FrontMatter, "front-matter", false, "write YAML front matter for Pandoc instead of a Markdown title")
	cmd.Flags().StringSliceVar(&only, "only", nil, "render only these slugs")
	cmd.Flags().StringVar(&single, "single", "", "write every document into this one file instead")
	cmd.Flags().BoolVar(&opts.LinkJSON, "json", false, "also write the machine-readable copy ("+render.ExportName+") and link it from the index")
	return cmd
}

func write(cmd *cobra.Command, path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "wrote", path)
	return nil
}
