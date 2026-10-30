# gocat

**An `ncat` clone in pure Go — standard library only, zero dependencies, single static binary.**

gocat covers the everyday `ncat` workflows (TCP/UDP client and listener, TLS, keep-open broker) and adds what you usually reach for `openssl s_client`, `curl -v` or `python -m http.server` for. These include a full TLS handshake and certificate-chain report, live TCP state from the kernel, a raw HTTP client and a one-command HTTP/HTTPS file server with an on-the-fly self-signed certificate.

```
gocat -v --ssl example.com:443          # who are you, really?
gocat -lnukv 4242                        # UDP listener, any peer, forever
gocat -l --ssl --http                    # HTTPS file server on ./ (self-signed)
```

---

## Features

| | |
|---|---|
| **TCP client / listener** | stdin → socket, socket → stdout, proper half-close (FIN on stdin EOF, keeps reading until the peer closes) |
| **UDP client / listener** | locked to the first peer by default, `-k` to follow any peer (replies go to the last sender), ICMP port-unreachable detection |
| **TLS client** | connects whatever the certificate (like `ncat --ssl`) but reports *everything*; legacy suites offered so old servers can be inspected; `--ssl-verify` for strict mode |
| **TLS listener** | self-signed ECDSA P-256 cert generated at startup (SAN = localhost, hostname, every local IP), or your own with `--ssl-cert/--ssl-key` |
| **Keep-open broker** (`-k`) | many TCP clients at once, everything received goes to stdout, stdin is broadcast to all clients |
| **HTTP client** (`--http`) | raw response (status line + headers + body, `curl -i` style), no redirect following, no compression, no proxy; `-X POST/PUT/PATCH` sends stdin as body |
| **HTTP(S) file server** (`-l --http`) | serves the current directory with listings, access log, request headers in verbose mode |
| **Verbose diagnostics** | DNS, every connect attempt with the reason it failed (RST / timeout / unreachable), handshake timings, TTFB, byte counters, kernel `TCP_INFO` on Linux |

## Installation

```sh
go install github.com/1mm0rt41PC/gocat@latest
```

Or from source:

```sh
git clone https://github.com/1mm0rt41PC/gocat
cd gocat
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o gocat .
```

Requires **Go 1.23+**. Built with Go 1.25 or later, gocat also reports the TLS key-exchange group (e.g. `X25519MLKEM768`).

Cross-compiling works out of the box (no cgo):

```sh
GOOS=windows GOARCH=amd64 go build -o gocat.exe .
GOOS=darwin  GOARCH=arm64 go build -o gocat-macos .
GOOS=linux   GOARCH=arm64 go build -o gocat-arm64 .
```

Tested targets: linux (amd64, arm64, arm, 386, mips, riscv64, s390x), windows/amd64, darwin/arm64, freebsd/amd64.

## Usage

```
gocat [options] <host>:<port>        connect (TCP by default)
gocat [options] <host> <port>
gocat -l [options] [<bind>:]<port>   listen
```

Short flags can be combined (`-lnuk`, `-luv`) and `ncat`-style `-p <port>` is accepted.

| Option | Description |
|---|---|
| `-l`, `--listen` | Listen mode |
| `-u`, `--udp` | UDP instead of TCP |
| `-k`, `--keep-open` | Listen: accept many TCP clients (stdin broadcast) / follow any UDP peer |
| `-n`, `--nodns` | Numeric addresses only — no DNS, no reverse DNS |
| `-v`, `--verbose` | Verbose. `-vv`: PEM chain, full ClientHello, per-datagram log, HTTP connection states |
| `-w`, `--wait <dur>` | Connect / TLS handshake timeout (default `10s`). UDP client: how long to wait for replies after stdin EOF (default `2s`). Accepts `5`, `1.5`, `500ms`… |
| `-C`, `--crlf` | Convert LF to CRLF on stdin |
| `-p <port>` | Port (ncat compatibility: `gocat -l -p 4242`) |
| `--ssl` | TLS. Client: no verification, full report. Listen: self-signed cert |
| `--ssl-verify` | TLS client with strict verification (fails on an invalid cert) |
| `--ssl-cert <file>`, `--ssl-key <file>` | Listen: use this PEM cert/key instead of a self-signed one |
| `--sni <name>` | Client: override SNI / name used for hostname verification |
| `--ssl-alpn <list>` | Comma-separated ALPN protocols, e.g. `h2,http/1.1` |
| `--http` | Client: send an HTTP request and print the raw response. Listen: static file server on the current directory |
| `-X`, `--method <m>` | HTTP client method (default `GET`) |
| `-h`, `--help` | Help |

**Default ports:** listen `31337`, `--http` listen `8080`, `--http --ssl` listen `8443`, HTTP client `80` / `443`.

## Examples

### Clients

```sh
gocat 10.0.0.1:445                      # TCP
gocat 10.0.0.1 445                      # same, ncat syntax
gocat [2001:db8::1]:22                  # IPv6
gocat -v 10.0.0.1:445                   # with connection diagnostics
gocat --ssl -v example.com:443          # TLS + full certificate report
gocat --ssl --sni internal.corp 10.0.0.5:443   # hit an IP, present another name
gocat -u 10.0.0.1:53                    # UDP
printf 'GET / HTTP/1.0\r\n\r\n' | gocat example.com:80
```

### HTTP client

```sh
gocat --http example.com                     # GET http://example.com/
gocat --http --ssl -v example.com/robots.txt # HTTPS + TLS report + request headers
gocat --http https://example.com:8443/api    # scheme prefix is understood
echo '{"a":1}' | gocat -X POST --http 127.0.0.1:8080/api
```

### Listeners

```sh
gocat -l 4242                           # TCP, one client, then exit
gocat -lk 4242                          # TCP broker, many clients
gocat -l --ssl -v 4443                  # TLS listener, self-signed, shows ClientHello
gocat -lu 4242                          # UDP
gocat -l -u -v 4242                     # UDP, verbose
gocat -lnukv 4242                       # UDP, any peer, forever, no DNS, verbose
gocat -l 127.0.0.1:4242                 # bind a specific address
```

### File server

```sh
gocat -l --http                         # http://<every local IP>:8080/
gocat -l --ssl --http                   # https://…:8443/ with a self-signed cert
gocat -l --ssl --http --ssl-cert c.pem --ssl-key k.pem 443
```

> ⚠️ The file server exposes the **whole current directory**, dotfiles included. Run it from the directory you actually mean to share.

### Quick file transfer

```sh
# receiver
gocat -l 4242 > dump.bin
# sender
gocat 10.0.0.1:4242 < dump.bin
```

## Verbose output

### TCP connection lifecycle

On Linux, gocat reads the kernel's `TCP_INFO` at each step: state, RTT, RTO, MSS, PMTU, congestion window, retransmissions and negotiated options. On other operating systems the event log is printed without kernel counters.

```
$ echo hello | gocat -v 127.0.0.1:4242
gocat: Connecting to 127.0.0.1:4242 (tcp) ...
gocat: Connected 127.0.0.1:58940 -> 127.0.0.1:4242 (3-way handshake 285µs)
gocat: TCP [established] state=ESTABLISHED rtt=0.03ms rttvar=0.02ms rto=204ms mss=32741 pmtu=65535 cwnd=10 unacked=0 retrans=0/0 lost=0 opts=timestamps,sack,wscale
gocat: stdin EOF -> half-close (FIN sent), still reading
gocat: TCP [after half-close] state=FIN_WAIT1 ...
gocat: Remote closed the connection (FIN received)
gocat: TCP [before close] state=CLOSE ...
gocat: 6 bytes sent, 0 bytes received in 583µs
```

Failures are explained instead of just reported:

```
$ gocat -v 127.0.0.1:1
gocat: Connecting to 127.0.0.1:1 (tcp) ...
gocat:   127.0.0.1:1: connection refused (TCP: RST, port closed / UDP: ICMP port unreachable) after 346µs
```

When a hostname resolves to several addresses, each one is tried in turn and every attempt is logged.

### TLS report

```
$ gocat --ssl -v localhost:4443
gocat: TLS handshake done in 1.25ms
gocat: TLS session:
gocat:   Version      : TLS 1.3
gocat:   Cipher suite : TLS_AES_128_GCM_SHA256 (0x1301)
gocat:   ALPN         : (none)
gocat:   SNI sent     : localhost
gocat:   Resumed      : false
gocat:   ECH accepted : false
gocat:   OCSP stapled : no
gocat:   SCTs (CT)    : 0
gocat:   Certificate chain sent by server (1):
gocat:    [0] Subject : CN=vm,O=gocat self-signed
gocat:       Issuer     : CN=vm,O=gocat self-signed
gocat:                    (self-issued)
gocat:       Serial     : 78:F8:85:D0:E6:49:92:21:3D:BC:D3:99:F7:93:F9:B7
gocat:       Validity   : 2026-10-29T16:24:12Z -> 2027-10-29T16:24:12Z (expires in 364 days)
gocat:       SAN        : DNS:localhost, DNS:vm, IP:127.0.0.1, IP:::1, IP:192.0.2.2
gocat:       Public key : ECDSA P-256
gocat:       Signature  : ECDSA-SHA256
gocat:       CA         : no
gocat:       Key usage  : DigitalSignature
gocat:       Ext usage  : serverAuth
gocat:       SHA-256    : 96:E2:14:E9:F3:05:E6:DA:EF:F3:47:A7:34:04:EC:2D:08:6C:76:02:20:58:10:77:4B:1F:77:3F:6A:72:00:DE
gocat:       SHA-1      : 26:0E:E0:A2:DE:CA:71:23:5D:8D:42:68:5D:05:0B:DF:2E:09:64:AF
gocat:       SPKI pin   : sha256/uT5lVutHY6HtbHdVeMWIj1z48gEufBq28R4ZWdufSVQ=
gocat:   Chain trust  : FAILED - x509: certificate signed by unknown authority
gocat:   Hostname     : OK (localhost)
```

For every certificate in the chain gocat prints the following, plus OCSP, CA Issuers (AIA) and CRL URLs when present:
- subject and issuer
- serial number
- validity, with the number of days remaining
- SANs (DNS, IP, email, URI)
- key type and size
- signature algorithm
- CA flag and path length
- key usage and extended key usage
- SHA-256 and SHA-1 fingerprints
- SPKI pin (HPKP format)

The chain is then validated against the system trust store. Every resulting **certification path** is printed. Certificates that come from the local store rather than from the server are marked `[from local store]`, which makes a missing intermediate obvious. Hostname verification is reported separately.

With `-vv` each certificate is also dumped as PEM, ready to pipe into other tools.

### TLS listener

On a TLS listener, verbose mode logs each ClientHello (SNI, ALPN). `-vv` adds the full list of offered versions, cipher suites and groups, which is handy for fingerprinting clients:

```
gocat: generated self-signed certificate (ECDSA P-256, 1 year)
gocat: TLS cert CN=vm SHA-256 96:E2:14:E9:...:00:DE
gocat: Listening on 127.0.0.1:4443 (tcp+tls)
gocat: Connection from 127.0.0.1:46940 (localhost) -> 127.0.0.1:4443
gocat: ClientHello from 127.0.0.1:46940: SNI="localhost" ALPN=[]
```

### HTTP client

```
$ gocat --http --ssl -v localhost:8443/
...TLS report...
gocat: > GET / HTTP/1.1
gocat: > Host: localhost:8443
gocat: > Accept: */*
gocat: > User-Agent: gocat/1.0
gocat: first response byte after 21.25ms (TTFB)
HTTP/1.1 200 OK
Content-Length: 107
Content-Type: text/html; charset=utf-8
...
gocat: 107 body bytes, total 21.39ms
```

Diagnostics go to **stderr** and data to **stdout**, so `gocat --http host/file > file` stays clean.

## Behaviour notes

- **`-n` means "no DNS"**, as in ncat, not verbose. Combine them explicitly: `-lnukv`.
- **TCP listener without `-k`**: gocat accepts one client, relays until it closes, then exits. A failed TLS handshake does not count, so it keeps waiting for the next client.
- **UDP is connectionless**: the client cannot tell an open port from a filtered one until a reply or an ICMP error comes back. After stdin EOF it waits `-w` (default 2 s) for late replies.
- **UDP listener without `-k`** locks onto the first peer and ignores (and logs) datagrams from others.
- **UDP over TLS (DTLS) is not supported.**
- **`--ssl` is deliberately permissive** (TLS 1.0+, insecure suites offered) because its job is inspection. Use `--ssl-verify` when you want a real trust decision.
- **No proxy**: `HTTP(S)_PROXY` environment variables are ignored on purpose. gocat always connects directly.

## Project layout

```
main.go            CLI parsing, TCP/UDP/TLS/HTTP client & server
tcpinfo_linux.go   kernel TCP_INFO via getsockopt (Linux)
tcpinfo_other.go   no-op on other OSes
kex_go125.go       TLS key-exchange group (Go ≥ 1.25)
kex_old.go         fallback for older toolchains
```

## Authorized use

gocat is a network diagnostics and administration tool. Only use it against systems you own or are explicitly authorized to test.