//go:build go1.25

package main

import "crypto/tls"

func keyExchange(cs tls.ConnectionState) string {
	if cs.CurveID == 0 {
		return ""
	}
	return cs.CurveID.String()
}
