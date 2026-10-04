// Command patchtacio alerts small IT teams when a product they run is actively
// exploited (CISA KEV) or approaching end-of-life.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/inconshreveable/mousetrap"
	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/logging"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	root := newRootCmd(defaultApp())
	if len(os.Args) == 1 && mousetrap.StartedByExplorer() {
		// Double-clicked in Explorer: open the web UI instead of cobra's
		// "this is a command line tool" message in a window that closes.
		cobra.MousetrapHelpText = ""
		root.SetArgs([]string{"ui"})
	}
	err := root.ExecuteContext(ctx)
	stop()
	if err != nil && !isOutcome(err) {
		fmt.Fprintln(os.Stderr, "Error:", logging.Clean(logging.RedactString(err.Error())))
	}
	os.Exit(exitCodeFor(err))
}
