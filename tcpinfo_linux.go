//go:build linux && !386 && !s390x

package main

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

var tcpStates = []string{"?", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
	"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"}

// tcpInfo reads the kernel TCP_INFO of the socket (state, RTT, cwnd, retransmits...).
func tcpInfo(c net.Conn) (string, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return "", false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return "", false
	}
	ti := &syscall.TCPInfo{}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		l := uint32(syscall.SizeofTCPInfo)
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(ti)), uintptr(unsafe.Pointer(&l)), 0)
	}); err != nil || errno != 0 {
		return "", false
	}
	st := "?"
	if int(ti.State) < len(tcpStates) {
		st = tcpStates[ti.State]
	}
	var opts []string
	for bit, n := range []string{"timestamps", "sack", "wscale", "ecn"} {
		if ti.Options&(1<<bit) != 0 {
			opts = append(opts, n)
		}
	}
	return fmt.Sprintf("state=%s rtt=%.2fms rttvar=%.2fms rto=%.0fms mss=%d pmtu=%d cwnd=%d unacked=%d retrans=%d/%d lost=%d opts=%s",
		st, float64(ti.Rtt)/1000, float64(ti.Rttvar)/1000, float64(ti.Rto)/1000, ti.Snd_mss, ti.Pmtu,
		ti.Snd_cwnd, ti.Unacked, ti.Retrans, ti.Total_retrans, ti.Lost, strings.Join(opts, ",")), true
}
