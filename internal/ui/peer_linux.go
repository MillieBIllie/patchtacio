//go:build linux

package ui

import (
	"log/slog"
	"net"
	"os"
)

// sameUserOnly refuses connections whose other end belongs to another user
// of this computer. Any local program can connect to 127.0.0.1; on Linux
// /proc/net/tcp says who owns the connecting socket, so another user's
// program never reaches a page, even holding a stolen link or cookie.
//
// A socket that cannot be found (another network namespace, /proc hidden)
// is let through: such a program cannot reach our 127.0.0.1 anyway.
func sameUserOnly(ln net.Listener, log *slog.Logger) net.Listener {
	return &peerListener{Listener: ln, log: log, uid: os.Getuid(), table: func() ([]byte, error) {
		return os.ReadFile("/proc/net/tcp")
	}}
}

type peerListener struct {
	net.Listener
	log   *slog.Logger
	uid   int
	table func() ([]byte, error)
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		remote, ok1 := c.RemoteAddr().(*net.TCPAddr)
		local, ok2 := c.LocalAddr().(*net.TCPAddr)
		if !ok1 || !ok2 {
			return c, nil
		}
		t, err := l.table()
		if err != nil {
			l.log.Debug("cannot read /proc/net/tcp; not checking the connecting user", "err", err)
			return c, nil
		}
		if uid, found := peerUID(t, remote, local); found && uid != l.uid {
			l.log.Warn("refused a connection from another user's program", "uid", uid)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}
