//go:build !linux || 386 || s390x

package main

import "net"

// TCP_INFO is Linux specific: other OSes only get the event log.
func tcpInfo(net.Conn) (string, bool) { return "", false }
