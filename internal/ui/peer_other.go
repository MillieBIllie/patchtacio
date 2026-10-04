//go:build !linux

package ui

import (
	"log/slog"
	"net"
)

// sameUserOnly returns ln unchanged: only Linux says, cheaply and without
// privileges, which user owns the other end of a local connection. Elsewhere
// the one-time link and the session cookie are the protection
// (docs/decisions/0005-m5-web-ui.md).
func sameUserOnly(ln net.Listener, _ *slog.Logger) net.Listener { return ln }
