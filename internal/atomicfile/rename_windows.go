package atomicfile

import (
	"fmt"
	"os"
	"time"
)

// rename retries briefly: on Windows, replacing a file fails while another
// process (a concurrent reader, an antivirus scanner, the search indexer)
// has it open.
func rename(from, to string) error {
	var err error
	for i := range 10 {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
	}
	return fmt.Errorf("rename after retries: %w", err)
}
