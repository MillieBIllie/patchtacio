// Command patchtacio alerts small IT teams when a product they run is actively
// exploited (CISA KEV) or approaching end-of-life.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/milliebillie/patchtacio/internal/logging"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := newRootCmd(defaultApp()).ExecuteContext(ctx)
	stop()
	if err != nil && !isOutcome(err) {
		fmt.Fprintln(os.Stderr, "Error:", logging.Clean(logging.RedactString(err.Error())))
	}
	os.Exit(exitCodeFor(err))
}
