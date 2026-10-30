// gocat - ncat-like tool in pure Go (stdlib only, zero dependencies).
//
//	gocat <host>:<port> | <host> <port>     TCP client
//	gocat --ssl -v <host>:<port>            TLS client + full handshake/cert report
//	gocat -u <host>:<port>                  UDP client
//	gocat --http [--ssl] -v <host>[:port][/path]   HTTP(S) client (curl -i like)
//	gocat -l [-u] [-k] [-n] [-v] [<bind>:]<port>   TCP/UDP listener
//	gocat -l --http [--ssl] [port]          file server on cwd (self-signed if --ssl)
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const version = "1.0"

const usage = `gocat ` + version + ` - ncat clone in pure Go (stdlib only)

Usage:
  gocat [options] <host>:<port>        connect (TCP by default)
  gocat [options] <host> <port>
  gocat -l [options] [<bind>:]<port>   listen (default port 31337, http 8080, https 8443)

Options:
  -l, --listen          listen mode
  -u, --udp             UDP instead of TCP
  -k, --keep-open       listen: accept many clients (TCP, stdin broadcast) / follow any peer (UDP)
  -n, --nodns           numeric addresses only, no DNS / reverse DNS
  -v, --verbose         verbose (-vv: PEM chain, full ClientHello, per-datagram, HTTP conn states)
  -w, --wait <dur>      connect/handshake timeout (default 10s). UDP client: idle wait after stdin EOF (default 2s)
  -C, --crlf            convert LF to CRLF on stdin
  -p <port>             port (ncat compat: gocat -l -p 4242)
      --ssl             TLS. Client: no verification but full report. Listen: self-signed cert generated on the fly
      --ssl-verify      TLS client with strict certificate verification (fails on invalid cert)
      --ssl-cert <f>    listen: PEM certificate (with --ssl-key) instead of self-signed
      --ssl-key <f>
      --sni <name>      client: override SNI / verification name
      --ssl-alpn <l>    comma separated ALPN list (e.g. h2,http/1.1)
      --http            client: HTTP request, response printed raw (status+headers+body)
                        listen: static file server on the current directory
  -X, --method <m>      HTTP client method (default GET; POST/PUT/PATCH send stdin as body)
  -h, --help

Examples:
  gocat 10.0.0.1:445
  gocat -v --ssl example.com:443
  gocat -v --http --ssl example.com/robots.txt
  gocat -lnuk 4242
  gocat -l --ssl --http 8443
`

type options struct {
	listen, udp, keep, noDNS bool
	ssl, sslVerify, http     bool
	crlf, timeoutSet         bool
	verbose                  int
	host, path, method, sni  string
	port                     int
	certFile, keyFile        string
	alpn                     []string
	timeout                  time.Duration
}

var opt options

func vlog(level int, format string, a ...any) {
	if opt.verbose >= level {
		fmt.Fprintf(os.Stderr, "gocat: "+format+"\n", a...)
	}
}

func info(format string, a ...any) { fmt.Fprintf(os.Stderr, "gocat: "+format+"\n", a...) }

func die(format string, a ...any) {
	info(format, a...)
	os.Exit(1)
}

func main() {
	parseArgs(os.Args[1:])
	var err error
	switch {
	case opt.listen && opt.http:
		err = runHTTPServer()
	case opt.listen && opt.udp:
		err = runUDPListen()
	case opt.listen:
		err = runTCPListen()
	case opt.http:
		err = runHTTPClient()
	case opt.udp:
		err = runUDPClient()
	default:
		err = runTCPClient()
	}
	if err != nil {
		die("%v", err)
	}
}

// ---------------------------------------------------------------- arguments

func parseArgs(args []string) {
	o := &opt
	o.timeout = 10 * time.Second
	o.method = "GET"
	var pos []string
	var pFlag string

	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(name, inline string, hasInline bool) string {
			if hasInline {
				return inline
			}
			if i+1 >= len(args) {
				die("option %s requires an argument", name)
			}
			i++
			return args[i]
		}
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "--"):
			name, v, has := strings.Cut(a[2:], "=")
			switch name {
			case "listen":
				o.listen = true
			case "udp":
				o.udp = true
			case "keep-open":
				o.keep = true
			case "nodns":
				o.noDNS = true
			case "verbose":
				o.verbose++
			case "crlf":
				o.crlf = true
			case "ssl":
				o.ssl = true
			case "ssl-verify":
				o.ssl, o.sslVerify = true, true
			case "http":
				o.http = true
			case "ssl-cert":
				o.certFile = val(a, v, has)
			case "ssl-key":
				o.keyFile = val(a, v, has)
			case "sni":
				o.sni = val(a, v, has)
			case "ssl-alpn":
				o.alpn = strings.Split(val(a, v, has), ",")
			case "method":
				o.method = strings.ToUpper(val(a, v, has))
			case "wait":
				setTimeout(val(a, v, has))
			case "help":
				fmt.Print(usage)
				os.Exit(0)
			default:
				die("unknown option %s (see --help)", a)
			}
		case len(a) > 1 && a[0] == '-':
		short:
			for j := 1; j < len(a); j++ {
				switch c := a[j]; c {
				case 'l':
					o.listen = true
				case 'u':
					o.udp = true
				case 'k':
					o.keep = true
				case 'n':
					o.noDNS = true
				case 'v':
					o.verbose++
				case 'C':
					o.crlf = true
				case 'h':
					fmt.Print(usage)
					os.Exit(0)
				case 'w', 'X', 'p':
					rest := a[j+1:]
					v := val("-"+string(c), rest, rest != "")
					switch c {
					case 'w':
						setTimeout(v)
					case 'X':
						o.method = strings.ToUpper(v)
					case 'p':
						pFlag = v
					}
					break short
				default:
					die("unknown option -%c (see --help)", c)
				}
			}
		default:
			pos = append(pos, a)
		}
	}
	resolveTarget(pos, pFlag)
}

func setTimeout(s string) {
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		opt.timeout = time.Duration(n * float64(time.Second))
	} else if d, err := time.ParseDuration(s); err == nil {
		opt.timeout = d
	} else {
		die("invalid timeout %q (e.g. 5, 1.5, 500ms)", s)
	}
	opt.timeoutSet = true
}

func resolveTarget(pos []string, pFlag string) {
	o := &opt
	var host, port string
	switch len(pos) {
	case 0:
	case 1:
		s := pos[0]
		if o.http && !o.listen {
			if r, ok := strings.CutPrefix(s, "https://"); ok {
				s, o.ssl = r, true
			} else if r, ok := strings.CutPrefix(s, "http://"); ok {
				s = r
			}
			if k := strings.IndexByte(s, '/'); k >= 0 {
				s, o.path = s[:k], s[k:]
			}
		}
		if o.listen && isNumber(s) {
			port = s
		} else {
			host, port = splitHostPort(s)
		}
	case 2:
		host, port = strings.Trim(pos[0], "[]"), pos[1]
	default:
		die("too many arguments (see --help)")
	}
	if pFlag != "" {
		port = pFlag
	}
	if o.path == "" {
		o.path = "/"
	}
	if port == "" {
		switch {
		case !o.listen && o.http && o.ssl:
			port = "443"
		case !o.listen && o.http:
			port = "80"
		case o.listen && o.http && o.ssl:
			port = "8443"
		case o.listen && o.http:
			port = "8080"
		case o.listen:
			port = "31337"
		default:
			die("missing port (usage: gocat <host>:<port> or gocat <host> <port>)")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		die("invalid port %q", port)
	}
	o.host, o.port = host, n

	switch {
	case !o.listen && host == "":
		die("missing host (see --help)")
	case o.udp && o.ssl:
		die("--ssl over UDP (DTLS) is not supported")
	case o.udp && o.http:
		die("--http over UDP makes no sense")
	case (o.certFile == "") != (o.keyFile == ""):
		die("--ssl-cert and --ssl-key go together")
	case o.certFile != "" && !o.ssl:
		o.ssl = true
	}
}

func splitHostPort(s string) (host, port string) {
	if strings.HasPrefix(s, "[") { // [v6]:port
		if k := strings.IndexByte(s, ']'); k > 0 {
			return s[1:k], strings.TrimPrefix(s[k+1:], ":")
		}
	}
	if strings.Count(s, ":") == 1 {
		h, p, _ := strings.Cut(s, ":")
		return h, p
	}
	return s, "" // hostname, IPv4, or bare IPv6 without port
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// ---------------------------------------------------------------- helpers

func dur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return d.Round(time.Microsecond).String()
	case d < time.Second:
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func describeErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused (TCP: RST, port closed / UDP: ICMP port unreachable)"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset by peer (RST)"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable (ICMP)"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable (no route)"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected EOF (TCP closed without TLS close_notify)"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout (no answer: filtered / dropped?)"
	}
	return err.Error()
}

func resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if opt.noDNS {
		return nil, fmt.Errorf("-n given but %q is not a numeric address", host)
	}
	t := time.Now()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution of %s failed: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	strs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
		strs = append(strs, a.IP.String())
	}
	vlog(1, "DNS %s -> %s (%s)", host, strings.Join(strs, ", "), dur(time.Since(t)))
	return ips, nil
}

func rdns(a net.Addr) string {
	if opt.noDNS || opt.verbose < 1 {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, h)
	if err != nil || len(names) == 0 {
		return ""
	}
	return " (" + strings.TrimSuffix(names[0], ".") + ")"
}

func logTCPInfo(c net.Conn, when string) {
	if opt.verbose < 1 || c == nil {
		return
	}
	if s, ok := tcpInfo(c); ok {
		vlog(1, "TCP [%s] %s", when, s)
	}
}

// dialTCP resolves then tries every address in order, reporting each attempt.
func dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: opt.timeout}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		vlog(1, "Connecting to %s (tcp) ...", addr)
		t := time.Now()
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			vlog(1, "  %s: %s after %s", addr, describeErr(err), dur(time.Since(t)))
			lastErr = err
			continue
		}
		vlog(1, "Connected %s -> %s (3-way handshake %s)", c.LocalAddr(), c.RemoteAddr(), dur(time.Since(t)))
		logTCPInfo(c, "established")
		return c, nil
	}
	return nil, fmt.Errorf("%s:%d: %s", host, port, describeErr(lastErr))
}

type counter struct {
	w io.Writer
	n *atomic.Int64
}

func (c counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// crlfReader turns lone LF into CRLF (-C).
type crlfReader struct {
	r      io.Reader
	pend   []byte
	lastCR bool
}

func (c *crlfReader) Read(p []byte) (int, error) {
	if len(c.pend) == 0 {
		buf := make([]byte, len(p)/2+1)
		n, err := c.r.Read(buf)
		if n == 0 {
			return 0, err
		}
		out := make([]byte, 0, n*2)
		for _, b := range buf[:n] {
			if b == '\n' && !c.lastCR {
				out = append(out, '\r')
			}
			out = append(out, b)
			c.lastCR = b == '\r'
		}
		c.pend = out
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

func stdin() io.Reader {
	if opt.crlf {
		return &crlfReader{r: os.Stdin}
	}
	return os.Stdin
}

// ---------------------------------------------------------------- stream relay

func closeWrite(conn, raw net.Conn) {
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.CloseWrite() // TLS close_notify
	}
	if t, ok := raw.(*net.TCPConn); ok {
		_ = t.CloseWrite() // FIN
	}
}

// relay: stdin -> conn, conn -> stdout. stdin EOF = half-close, keep reading
// until the remote side closes (ncat default behaviour).
func relay(conn, raw net.Conn) {
	start := time.Now()
	var sent, recv atomic.Int64
	go func() {
		_, err := io.Copy(counter{conn, &sent}, stdin())
		if err != nil {
			vlog(1, "send error: %s", describeErr(err))
			return
		}
		vlog(1, "stdin EOF -> half-close (FIN sent), still reading")
		closeWrite(conn, raw)
		logTCPInfo(raw, "after half-close")
	}()
	_, err := io.Copy(counter{os.Stdout, &recv}, conn)
	if err == nil {
		vlog(1, "Remote closed the connection (FIN received)")
	} else {
		vlog(1, "Connection ended: %s", describeErr(err))
	}
	logTCPInfo(raw, "before close")
	conn.Close()
	vlog(1, "%d bytes sent, %d bytes received in %s", sent.Load(), recv.Load(), dur(time.Since(start)))
}

// ---------------------------------------------------------------- TCP client

func runTCPClient() error {
	raw, err := dialTCP(context.Background(), opt.host, opt.port)
	if err != nil {
		return err
	}
	conn := raw
	if opt.ssl {
		tc, err := tlsClientHandshake(raw, opt.host)
		if err != nil {
			return err
		}
		conn = tc
	}
	relay(conn, raw)
	return nil
}

// ---------------------------------------------------------------- TLS

func verifyName(host string) string {
	if opt.sni != "" {
		return opt.sni
	}
	return host
}

func clientTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{
		ServerName: verifyName(host), // not sent as SNI when it is an IP
		NextProtos: opt.alpn,
		MinVersion: tls.VersionTLS10,
	}
	if !opt.sslVerify {
		// like ncat --ssl: connect whatever the cert, but report everything.
		// Offer legacy suites too so old servers can be inspected.
		cfg.InsecureSkipVerify = true
		for _, cs := range tls.CipherSuites() {
			cfg.CipherSuites = append(cfg.CipherSuites, cs.ID)
		}
		for _, cs := range tls.InsecureCipherSuites() {
			cfg.CipherSuites = append(cfg.CipherSuites, cs.ID)
		}
	}
	return cfg
}

func tlsClientHandshake(raw net.Conn, host string) (*tls.Conn, error) {
	tc := tls.Client(raw, clientTLSConfig(host))
	t := time.Now()
	_ = tc.SetDeadline(time.Now().Add(opt.timeout))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	_ = tc.SetDeadline(time.Time{})
	vlog(1, "TLS handshake done in %s", dur(time.Since(t)))
	printTLS(tc.ConnectionState(), verifyName(host), false)
	return tc, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func colonHex(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}

func printTLS(cs tls.ConnectionState, name string, server bool) {
	if opt.verbose < 1 {
		return
	}
	vlog(1, "TLS session:")
	vlog(1, "  Version      : %s", tls.VersionName(cs.Version))
	vlog(1, "  Cipher suite : %s (0x%04X)", tls.CipherSuiteName(cs.CipherSuite), cs.CipherSuite)
	if k := keyExchange(cs); k != "" {
		vlog(1, "  Key exchange : %s", k)
	}
	vlog(1, "  ALPN         : %s", orNone(cs.NegotiatedProtocol))
	if server {
		vlog(1, "  SNI received : %s", orNone(cs.ServerName))
	} else {
		vlog(1, "  SNI sent     : %s", orNone(cs.ServerName))
		vlog(1, "  Resumed      : %v", cs.DidResume)
		vlog(1, "  ECH accepted : %v", cs.ECHAccepted)
		if len(cs.OCSPResponse) > 0 {
			vlog(1, "  OCSP stapled : yes (%d bytes)", len(cs.OCSPResponse))
		} else {
			vlog(1, "  OCSP stapled : no")
		}
		vlog(1, "  SCTs (CT)    : %d", len(cs.SignedCertificateTimestamps))
	}
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		if !server {
			vlog(1, "  No peer certificate")
		}
		return
	}
	who := "server"
	if server {
		who = "client"
	}
	vlog(1, "  Certificate chain sent by %s (%d):", who, len(certs))
	for i, c := range certs {
		printCert(i, c)
	}
	printVerify(certs, name)
}

var kuNames = []string{"DigitalSignature", "ContentCommitment", "KeyEncipherment", "DataEncipherment",
	"KeyAgreement", "CertSign", "CRLSign", "EncipherOnly", "DecipherOnly"}

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping: "timeStamping", x509.ExtKeyUsageOCSPSigning: "OCSPSigning",
}

func keyDesc(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits (e=%d)", k.N.BitLen(), k.E)
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

func validity(c *x509.Certificate) string {
	now := time.Now()
	switch {
	case now.Before(c.NotBefore):
		return "NOT YET VALID"
	case now.After(c.NotAfter):
		return fmt.Sprintf("EXPIRED %d days ago", int(now.Sub(c.NotAfter).Hours()/24))
	}
	return fmt.Sprintf("expires in %d days", int(c.NotAfter.Sub(now).Hours()/24))
}

func printCert(i int, c *x509.Certificate) {
	p := func(f string, a ...any) { vlog(1, "      "+f, a...) }
	vlog(1, "   [%d] Subject : %s", i, c.Subject)
	p("Issuer     : %s", c.Issuer)
	if string(c.RawSubject) == string(c.RawIssuer) {
		p("             (self-issued)")
	}
	p("Serial     : %s", colonHex(c.SerialNumber.Bytes()))
	p("Validity   : %s -> %s (%s)", c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), validity(c))
	var san []string
	for _, d := range c.DNSNames {
		san = append(san, "DNS:"+d)
	}
	for _, ip := range c.IPAddresses {
		san = append(san, "IP:"+ip.String())
	}
	for _, e := range c.EmailAddresses {
		san = append(san, "email:"+e)
	}
	for _, u := range c.URIs {
		san = append(san, "URI:"+u.String())
	}
	if len(san) > 0 {
		p("SAN        : %s", strings.Join(san, ", "))
	}
	p("Public key : %s", keyDesc(c.PublicKey))
	p("Signature  : %s", c.SignatureAlgorithm)
	if c.BasicConstraintsValid {
		if c.IsCA {
			pl := "unlimited"
			if c.MaxPathLen > 0 || c.MaxPathLenZero {
				pl = strconv.Itoa(c.MaxPathLen)
			}
			p("CA         : yes (pathlen %s)", pl)
		} else {
			p("CA         : no")
		}
	}
	var ku []string
	for b, n := range kuNames {
		if c.KeyUsage&(1<<b) != 0 {
			ku = append(ku, n)
		}
	}
	if len(ku) > 0 {
		p("Key usage  : %s", strings.Join(ku, ", "))
	}
	var eku []string
	for _, e := range c.ExtKeyUsage {
		eku = append(eku, ekuNames[e])
	}
	for _, o := range c.UnknownExtKeyUsage {
		eku = append(eku, o.String())
	}
	if len(eku) > 0 {
		p("Ext usage  : %s", strings.Join(eku, ", "))
	}
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw)
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	p("SHA-256    : %s", colonHex(s256[:]))
	p("SHA-1      : %s", colonHex(s1[:]))
	p("SPKI pin   : sha256/%s", base64.StdEncoding.EncodeToString(spki[:]))
	if len(c.OCSPServer) > 0 {
		p("OCSP       : %s", strings.Join(c.OCSPServer, ", "))
	}
	if len(c.IssuingCertificateURL) > 0 {
		p("CA issuers : %s", strings.Join(c.IssuingCertificateURL, ", "))
	}
	if len(c.CRLDistributionPoints) > 0 {
		p("CRL        : %s", strings.Join(c.CRLDistributionPoints, ", "))
	}
	if opt.verbose >= 2 {
		_ = pem.Encode(os.Stderr, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
}

func shortName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func printVerify(certs []*x509.Certificate, name string) {
	inter := x509.NewCertPool()
	sent := map[string]bool{}
	for i, c := range certs {
		sent[string(c.Raw)] = true
		if i > 0 {
			inter.AddCert(c)
		}
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Intermediates: inter})
	if err != nil {
		vlog(1, "  Chain trust  : FAILED - %v", err)
	} else {
		vlog(1, "  Chain trust  : OK (system trust store)")
	}
	for i, ch := range chains {
		parts := make([]string, 0, len(ch))
		for _, c := range ch {
			s := shortName(c)
			if !sent[string(c.Raw)] {
				s += " [from local store]"
			}
			parts = append(parts, s)
		}
		vlog(1, "  Path #%d      : %s", i+1, strings.Join(parts, "  ->  "))
	}
	if name != "" {
		if err := certs[0].VerifyHostname(name); err != nil {
			vlog(1, "  Hostname     : MISMATCH - %v", err)
		} else {
			vlog(1, "  Hostname     : OK (%s)", name)
		}
	}
}

// ---------------------------------------------------------------- TLS server side

func localIPs() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "localhost"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hn, Organization: []string{"gocat self-signed"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", hn},
		IPAddresses:           localIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func versionNames(vs []uint16) string {
	s := make([]string, 0, len(vs))
	for _, v := range vs {
		s = append(s, tls.VersionName(v))
	}
	return strings.Join(s, ", ")
}

func logClientHello(h *tls.ClientHelloInfo) {
	vlog(1, "ClientHello from %s: SNI=%q ALPN=%v", h.Conn.RemoteAddr(), h.ServerName, h.SupportedProtos)
	if opt.verbose >= 2 {
		cs := make([]string, 0, len(h.CipherSuites))
		for _, c := range h.CipherSuites {
			cs = append(cs, tls.CipherSuiteName(c))
		}
		cv := make([]string, 0, len(h.SupportedCurves))
		for _, c := range h.SupportedCurves {
			cv = append(cv, c.String())
		}
		vlog(2, "  versions : %s", versionNames(h.SupportedVersions))
		vlog(2, "  ciphers  : %s", strings.Join(cs, ", "))
		vlog(2, "  groups   : %s", strings.Join(cv, ", "))
	}
}

func serverTLSConfig(protos []string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if opt.certFile != "" {
		if cert, err = tls.LoadX509KeyPair(opt.certFile, opt.keyFile); err != nil {
			return nil, err
		}
		if cert.Leaf == nil {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
	} else {
		if cert, err = selfSigned(); err != nil {
			return nil, err
		}
		info("generated self-signed certificate (ECDSA P-256, 1 year)")
	}
	fp := sha256.Sum256(cert.Leaf.Raw)
	info("TLS cert CN=%s SHA-256 %s", cert.Leaf.Subject.CommonName, colonHex(fp[:]))
	if opt.alpn != nil {
		protos = opt.alpn
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		NextProtos:   protos,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			logClientHello(h)
			return nil, nil
		},
	}, nil
}

// ---------------------------------------------------------------- TCP listen

func serverAccept(raw net.Conn, cfg *tls.Config) (net.Conn, error) {
	vlog(1, "Connection from %s%s -> %s", raw.RemoteAddr(), rdns(raw.RemoteAddr()), raw.LocalAddr())
	logTCPInfo(raw, "accepted")
	if cfg == nil {
		return raw, nil
	}
	tc := tls.Server(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(opt.timeout))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake with %s failed: %w", raw.RemoteAddr(), err)
	}
	_ = tc.SetDeadline(time.Time{})
	printTLS(tc.ConnectionState(), "", true)
	return tc, nil
}

func runTCPListen() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(opt.host, strconv.Itoa(opt.port)))
	if err != nil {
		return err
	}
	var cfg *tls.Config
	if opt.ssl {
		if cfg, err = serverTLSConfig(nil); err != nil {
			return err
		}
	}
	mode := "tcp"
	if opt.ssl {
		mode = "tcp+tls"
	}
	vlog(1, "Listening on %s (%s)%s", ln.Addr(), mode, map[bool]string{true: ", keep-open", false: ""}[opt.keep])

	if !opt.keep {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return err
			}
			conn, err := serverAccept(raw, cfg)
			if err != nil { // failed TLS handshake: wait for the next one
				vlog(1, "%v", err)
				continue
			}
			ln.Close()
			relay(conn, raw)
			return nil
		}
	}
	return broker(ln, cfg)
}

// broker (-k): many clients, everything received goes to stdout,
// stdin is broadcast to every connected client.
func broker(ln net.Listener, cfg *tls.Config) error {
	var mu sync.Mutex
	clients := map[net.Conn]struct{}{}
	out := &lockedWriter{w: os.Stdout}

	go func() {
		buf := make([]byte, 32*1024)
		r := stdin()
		for {
			n, err := r.Read(buf)
			if n > 0 {
				mu.Lock()
				if len(clients) == 0 {
					vlog(1, "no client connected: %d bytes from stdin dropped", n)
				}
				for c := range clients {
					if _, werr := c.Write(buf[:n]); werr != nil {
						vlog(1, "write to %s: %s", c.RemoteAddr(), describeErr(werr))
					}
				}
				mu.Unlock()
			}
			if err != nil {
				vlog(1, "stdin EOF (still accepting clients)")
				return
			}
		}
	}()

	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			conn, err := serverAccept(raw, cfg)
			if err != nil {
				vlog(1, "%v", err)
				return
			}
			mu.Lock()
			clients[conn] = struct{}{}
			n := len(clients)
			mu.Unlock()
			vlog(1, "%d client(s) connected", n)

			start := time.Now()
			got, err := io.Copy(out, conn)
			reason := "FIN received"
			if err != nil {
				reason = describeErr(err)
			}
			mu.Lock()
			delete(clients, conn)
			n = len(clients)
			mu.Unlock()
			logTCPInfo(raw, "before close")
			conn.Close()
			vlog(1, "%s disconnected (%s): %d bytes received in %s, %d client(s) left",
				raw.RemoteAddr(), reason, got, dur(time.Since(start)), n)
		}()
	}
}

// ---------------------------------------------------------------- UDP

func runUDPClient() error {
	ips, err := resolve(context.Background(), opt.host)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(opt.port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	vlog(1, "UDP socket %s -> %s (connectionless: nothing proves the port is open until a reply or ICMP comes back)",
		conn.LocalAddr(), conn.RemoteAddr())

	idle := 2 * time.Second
	if opt.timeoutSet {
		idle = opt.timeout
	}
	start := time.Now()
	var sent, recv, dgOut, dgIn atomic.Int64
	var eof atomic.Bool

	go func() {
		buf := make([]byte, 65507)
		r := stdin()
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					vlog(1, "send: %s", describeErr(werr))
				} else {
					sent.Add(int64(n))
					dgOut.Add(1)
					vlog(2, "-> %d bytes datagram", n)
				}
			}
			if err != nil {
				eof.Store(true)
				vlog(1, "stdin EOF, waiting up to %s for replies", idle)
				_ = conn.SetReadDeadline(time.Now().Add(idle))
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	var rerr error
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			recv.Add(int64(n))
			dgIn.Add(1)
			vlog(2, "<- %d bytes datagram from %s", n, conn.RemoteAddr())
			os.Stdout.Write(buf[:n])
			if eof.Load() {
				_ = conn.SetReadDeadline(time.Now().Add(idle))
			}
		}
		if err != nil {
			var ne net.Error
			if !(errors.As(err, &ne) && ne.Timeout()) {
				rerr = fmt.Errorf("%s", describeErr(err))
			}
			break
		}
	}
	vlog(1, "%d bytes sent (%d datagrams), %d bytes received (%d datagrams) in %s",
		sent.Load(), dgOut.Load(), recv.Load(), dgIn.Load(), dur(time.Since(start)))
	return rerr
}

func runUDPListen() error {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(opt.host, strconv.Itoa(opt.port)))
	if err != nil {
		return err
	}
	defer pc.Close()
	if opt.keep {
		vlog(1, "Listening on %s (udp, keep-open: any peer, replies go to the last one)", pc.LocalAddr())
	} else {
		vlog(1, "Listening on %s (udp, locked to the first peer; -k to accept any)", pc.LocalAddr())
	}

	var mu sync.Mutex
	var peer net.Addr

	go func() {
		buf := make([]byte, 65507)
		r := stdin()
		for {
			n, err := r.Read(buf)
			if n > 0 {
				mu.Lock()
				p := peer
				mu.Unlock()
				if p == nil {
					vlog(1, "no peer yet: %d bytes from stdin dropped", n)
				} else if _, werr := pc.WriteTo(buf[:n], p); werr != nil {
					vlog(1, "send to %s: %s", p, describeErr(werr))
				} else {
					vlog(2, "-> %d bytes to %s", n, p)
				}
			}
			if err != nil {
				vlog(1, "stdin EOF (still listening)")
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Windows reports ICMP port unreachable as WSAECONNRESET here: ignore
			vlog(1, "recv: %s", describeErr(err))
			continue
		}
		mu.Lock()
		switch {
		case peer == nil:
			peer = from
			vlog(1, "Datagram from new peer %s%s", from, rdns(from))
		case from.String() != peer.String():
			if !opt.keep {
				p := peer
				mu.Unlock()
				vlog(1, "ignored %d bytes from %s (locked to %s, use -k)", n, from, p)
				continue
			}
			peer = from
			vlog(1, "New peer %s%s (replies now go there)", from, rdns(from))
		}
		mu.Unlock()
		vlog(1, "<- %d bytes from %s", n, from)
		os.Stdout.Write(buf[:n])
	}
}

// ---------------------------------------------------------------- HTTP client

func runHTTPClient() error {
	scheme, defPort := "http", 80
	if opt.ssl {
		scheme, defPort = "https", 443
	}
	hostport := net.JoinHostPort(opt.host, strconv.Itoa(opt.port))
	hostHeader := hostport
	if opt.port == defPort {
		hostHeader = opt.host
		if strings.Contains(opt.host, ":") {
			hostHeader = "[" + opt.host + "]"
		}
	}
	url := scheme + "://" + hostport + opt.path

	var raw net.Conn
	tr := &http.Transport{
		Proxy: nil, // direct, like ncat
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := dialTCP(ctx, opt.host, opt.port)
			raw = c
			return c, err
		},
		TLSClientConfig:       clientTLSConfig(opt.host),
		TLSHandshakeTimeout:   opt.timeout,
		ResponseHeaderTimeout: opt.timeout * 3,
		DisableCompression:    true,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var body io.Reader
	switch opt.method {
	case "POST", "PUT", "PATCH":
		body = stdin()
	}
	req, err := http.NewRequest(opt.method, url, body)
	if err != nil {
		return err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "gocat/"+version)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	var tlsStart time.Time
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			vlog(1, "TLS handshake done in %s", dur(time.Since(tlsStart)))
			printTLS(cs, verifyName(opt.host), false)
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			if opt.verbose >= 1 {
				vlog(1, "> %s %s HTTP/1.1", req.Method, opt.path)
				vlog(1, "> Host: %s", req.Host)
				keys := make([]string, 0, len(req.Header))
				for k := range req.Header {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					vlog(1, "> %s: %s", k, strings.Join(req.Header[k], ", "))
				}
			}
		},
		GotFirstResponseByte: func() {
			vlog(1, "first response byte after %s (TTFB)", dur(time.Since(start)))
			logTCPInfo(raw, "response")
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s", describeErr(err))
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stdout, "%s %s\r\n", resp.Proto, resp.Status)
	_ = resp.Header.Write(os.Stdout)
	fmt.Fprint(os.Stdout, "\r\n")
	n, err := io.Copy(os.Stdout, resp.Body)
	if err != nil {
		vlog(1, "body read: %s", describeErr(err))
	}
	vlog(1, "%d body bytes, total %s", n, dur(time.Since(start)))
	return nil
}

// ---------------------------------------------------------------- HTTP server

type statusRW struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *statusRW) WriteHeader(s int) {
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}

func (w *statusRW) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusRW{ResponseWriter: w}
		h.ServeHTTP(sw, r)
		info("%s %s %s %s -> %d (%d bytes, %s) %q", start.Format("15:04:05"), r.RemoteAddr,
			r.Method, r.RequestURI, sw.status, sw.n, dur(time.Since(start)), r.UserAgent())
		if opt.verbose >= 1 {
			if r.TLS != nil {
				vlog(1, "  TLS %s %s SNI=%q", tls.VersionName(r.TLS.Version),
					tls.CipherSuiteName(r.TLS.CipherSuite), r.TLS.ServerName)
			}
			keys := make([]string, 0, len(r.Header))
			for k := range r.Header {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				vlog(1, "  < %s: %s", k, strings.Join(r.Header[k], ", "))
			}
		}
	})
}

func listenURLs(scheme string, a net.Addr) []string {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return []string{scheme + "://" + a.String() + "/"}
	}
	port := strconv.Itoa(tcp.Port)
	if !tcp.IP.IsUnspecified() {
		return []string{scheme + "://" + net.JoinHostPort(tcp.IP.String(), port) + "/"}
	}
	var urls []string
	for _, ip := range localIPs() {
		urls = append(urls, scheme+"://"+net.JoinHostPort(ip.String(), port)+"/")
	}
	return urls
}

func runHTTPServer() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(opt.host, strconv.Itoa(opt.port)))
	if err != nil {
		return err
	}
	scheme := "http"
	if opt.ssl {
		cfg, err := serverTLSConfig([]string{"http/1.1"})
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, cfg)
		scheme = "https"
	}
	info("serving %s on:", dir)
	for _, u := range listenURLs(scheme, ln.Addr()) {
		info("  %s", u)
	}
	srv := &http.Server{
		Handler:           logRequests(http.FileServer(http.Dir(dir))),
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          log.New(os.Stderr, "gocat: ", 0),
	}
	if opt.verbose >= 2 {
		srv.ConnState = func(c net.Conn, s http.ConnState) {
			vlog(2, "conn %s %s", c.RemoteAddr(), s)
		}
	}
	return srv.Serve(ln)
}
