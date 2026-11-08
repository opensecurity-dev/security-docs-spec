package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

func newInitCmd() *cobra.Command {
	var org, product, out string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter document set where every claim is todo",
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := spec.Marshal(spec.Scaffold(org, product))
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				_, err := cmd.OutOrStdout().Write(b)
				return err
			}
			if !force {
				if _, err := os.Stat(out); err == nil {
					return fmt.Errorf("%s exists; use --force to overwrite", out)
				}
			}
			return os.WriteFile(out, b, 0o600)
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "organization name")
	cmd.Flags().StringVar(&product, "product", "", "product name")
	cmd.Flags().StringVarP(&out, "output", "o", "", "file to write (default stdout)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	if err := cmd.MarkFlagRequired("org"); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired("product"); err != nil {
		panic(err)
	}
	return cmd
}
