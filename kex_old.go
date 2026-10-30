//go:build !go1.25

package main

import "crypto/tls"

// ConnectionState.CurveID only exists since Go 1.25.
func keyExchange(tls.ConnectionState) string { return "" }
