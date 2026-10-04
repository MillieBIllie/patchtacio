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

// procTCPAddr writes an IPv4 TCP address as /proc/net/tcp does: the address
// as a host-order (little-endian on every Linux Go supports) 32-bit hex
// number, then the port in hex, e.g. 127.0.0.1:8080 is "0100007F:1F90".
func procTCPAddr(a *net.TCPAddr) (string, bool) {
	ip4 := a.IP.To4()
	if ip4 == nil {
		return "", false
	}
	return fmt.Sprintf("%08X:%04X", binary.LittleEndian.Uint32(ip4), a.Port), true
}

// peerUID finds, in the contents of /proc/net/tcp, the socket at the other
// end of a connection the server accepted (its local address is the
// connection's remote address, and its remote address is ours) and returns
// the user that owns it.
func peerUID(table []byte, remote, local *net.TCPAddr) (uid int, found bool) {
	want, ok1 := procTCPAddr(remote)
	peer, ok2 := procTCPAddr(local)
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
