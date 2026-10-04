package ui

import (
	"errors"
	"strings"
)

// OpenBrowser opens u, which must be a link to this computer's UI, in the
// default browser. It returns once the browser has been asked; the caller
// prints the link as well, in case nothing opens.
func OpenBrowser(u string) error {
	if !strings.HasPrefix(u, "http://127.0.0.1:") || strings.ContainsAny(u, " \t\r\n\"'`") {
		return errors.New("refusing to open a link that is not Patchtacio's own")
	}
	return openBrowser(u)
}
