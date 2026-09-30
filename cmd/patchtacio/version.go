package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/version"
)

func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(info); err != nil {
					return fmt.Errorf("encode version info: %w", err)
				}
				return nil
			}
			_, err := fmt.Fprintf(out, "patchtacio %s\n  commit:   %s\n  built:    %s\n  go:       %s\n  platform: %s\n",
				info.Version, info.Commit, info.Date, info.GoVersion, info.Platform)
			if err != nil {
				return fmt.Errorf("write version info: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}
