package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/security-docs-spec/render"
	"github.com/opensecurity-dev/security-docs-spec/schema"
	"github.com/opensecurity-dev/security-docs-spec/spec"
)

func newSecurityTxtCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "security-txt FILE",
		Short: "Write an RFC 9116 security.txt from the security-response document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := spec.Load(args[0])
			if err != nil {
				return err
			}
			s, err := render.SecurityTxt(set)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), s)
			return err
		},
	}
}

func newExportCmd() *cobra.Command {
	var audience string
	var draft bool
	cmd := &cobra.Command{
		Use:   "export FILE",
		Short: "Write the machine-readable copy of what render publishes for an audience",
		Long: `export prints the document set filtered for --audience, as JSON. It is
the machine-readable twin of render's Markdown: both come from the same
filtered view. It refuses a set with unassessed claims unless --draft.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := spec.Load(args[0])
			if err != nil {
				return err
			}
			b, err := render.ExportJSON(set, spec.Visibility(audience), draft)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	cmd.Flags().StringVar(&audience, "audience", "public", "widest visibility to export: public, nda or internal")
	cmd.Flags().BoolVar(&draft, "draft", false, "export even with unassessed claims")
	return cmd
}

func newSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema for document sets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write(schema.JSON)
			return err
		},
	}
}
