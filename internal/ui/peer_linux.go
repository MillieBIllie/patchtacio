//go:build linux

package ui

import (
	"log/slog"
	"net"
	"os"
)

// sameUserOnly refuses connections whose other end belongs to another user
// of this computer. Any local program can connect to 127.0.0.1; on Linux
// /proc/net/tcp and tcp6 (an IPv6 socket can connect to ::ffff:127.0.0.1)
// say who owns the connecting socket, so another user's program never
// reaches a page, even holding a stolen link or cookie.
//
// A connected client socket is always listed, so one that is not found is
// refused. Only when /proc/net cannot be read at all (hidden /proc) is the
// check skipped, with a warning.
func sameUserOnly(ln net.Listener, log *slog.Logger) net.Listener {
	return &peerListener{Listener: ln, log: log, uid: os.Getuid(), table: func(v6 bool) ([]byte, error) {
		if v6 {
			return os.ReadFile("/proc/net/tcp6")
		}
		return os.ReadFile("/proc/net/tcp")
	}}
}

type peerListener struct {
	net.Listener
	log   *slog.Logger
	uid   int
	table func(v6 bool) ([]byte, error)
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allowed(c) {
			return c, nil
		}
		_ = c.Close()
	}
}

func (l *peerListener) allowed(c net.Conn) bool {
	remote, ok1 := c.RemoteAddr().(*net.TCPAddr)
	local, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return false
	}
	readable := false
	for _, v6 := range []bool{false, true} {
		t, err := l.table(v6)
		if err != nil {
			continue // no IPv6 on this kernel, say
		}
		readable = true
		if uid, found := peerUID(t, remote, local, v6); found {
			if uid != l.uid {
				l.log.Warn("refused a connection from another user's program", "uid", uid)
				return false
			}
			return true
		}
	}
	if !readable {
		l.log.Warn("cannot read /proc/net/tcp; not checking which user connects")
		return true
	}
	l.log.Warn("refused a connection whose owner could not be found")
	return false
}
