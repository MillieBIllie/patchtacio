package ui

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// procAddr writes a TCP address as /proc/net/tcp (IPv4) or /proc/net/tcp6
// (v6 true) does: the address as 32-bit words in host byte order, in hex,
// then the port in hex. 127.0.0.1:8080 is "0100007F:1F90" in tcp on a
// little-endian machine, and "0000000000000000FFFF00000100007F:1F90" in tcp6,
// where an IPv6 socket connected to ::ffff:127.0.0.1 is listed.
func procAddr(a *net.TCPAddr, v6 bool) (string, bool) {
	ip := a.IP.To4()
	if ip == nil {
		return "", false // our listener is IPv4: both ends are IPv4 addresses
	}
	if v6 {
		ip = ip.To16() // ::ffff:a.b.c.d
	}
	var b strings.Builder
	for i := 0; i < len(ip); i += 4 {
		fmt.Fprintf(&b, "%08X", binary.NativeEndian.Uint32(ip[i:i+4]))
	}
	fmt.Fprintf(&b, ":%04X", a.Port)
	return b.String(), true
}

// peerUID finds, in the contents of /proc/net/tcp (v6 false) or tcp6, the
// socket at the other end of a connection the server accepted: its local
// address is the connection's remote address, and its remote address is
// ours. It returns the user that owns that socket.
func peerUID(table []byte, remote, local *net.TCPAddr, v6 bool) (uid int, found bool) {
	want, ok1 := procAddr(remote, v6)
	peer, ok2 := procAddr(local, v6)
	if !ok1 || !ok2 {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(table))
	for sc.Scan() {
		// sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != want || f[2] != peer {
			continue
		}
		n, err := strconv.Atoi(f[7])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
