package main

import (
	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/version"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patchtacio",
		Short: "Alerts for exploited and end-of-life products in your stack",
		Long: "Patchtacio tells you when a product you run appears in the CISA Known Exploited\n" +
			"Vulnerabilities catalog or is approaching end-of-life, in plain language.\n\n" +
			exitCodesHelp,
		Version:       version.Get().Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newVersionCmd())
	return cmd
}
