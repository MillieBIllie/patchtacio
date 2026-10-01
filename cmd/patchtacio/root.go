package main

import (
	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/version"
)

func newRootCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patchtacio",
		Short: "Alerts for exploited and end-of-life products in your stack",
		Long: "Patchtacio tells you when a product you run appears in the CISA Known Exploited\n" +
			"Vulnerabilities catalog or is approaching end-of-life, in plain language.\n\n" +
			exitCodesHelp,
		Version:       version.Get().Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			a.setupLogging(cmd.ErrOrStderr())
		},
	}
	// Defining -v here takes it from cobra's automatic --version shorthand;
	// --version keeps working.
	cmd.PersistentFlags().CountVarP(&a.verbosity, "verbose", "v", "show more detail on stderr (-v info, -vv debug)")
	cmd.PersistentFlags().BoolVarP(&a.quiet, "quiet", "q", false, "print only warnings and errors")
	cmd.MarkFlagsMutuallyExclusive("verbose", "quiet")

	cmd.AddCommand(newVersionCmd(), newFeedsCmd(a))
	return cmd
}
