// Command patchtacio alerts small IT teams when a product they run is actively
// exploited (CISA KEV) or approaching end-of-life.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := newRootCmd(defaultApp()).ExecuteContext(ctx)
	stop()
	if err != nil && !isOutcome(err) {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	os.Exit(exitCodeFor(err))
}
