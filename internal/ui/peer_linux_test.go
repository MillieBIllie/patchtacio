//go:build linux

package ui

import (
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestSameUserOnlyOnLinux(t *testing.T) {
	var lc net.ListenConfig
	raw, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()

	// Our own connection is found in the real /proc/net/tcp and let in.
	ln := sameUserOnly(raw, slog.New(slog.DiscardHandler))
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(t.Context(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	select {
	case s := <-accepted:
		_ = s.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("own connection was not accepted")
	}

	// A connection owned by another uid is closed, and Accept waits on.
	pl := ln.(*peerListener)
	pl.uid = os.Getuid() + 1
	go func() {
		c, err := pl.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c2, err := d.DialContext(t.Context(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Error("connection from another user was not closed")
	}
	select {
	case <-accepted:
		t.Error("connection from another user was accepted")
	case <-time.After(100 * time.Millisecond):
	}
}
