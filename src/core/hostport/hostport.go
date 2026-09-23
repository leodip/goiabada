// Package hostport joins a configured host and port into the address net.Listen and net.Dial
// take, and is the one place in this tree that does.
//
// A host here is what a field carrying no port holds: a name or a bare address, such as `db`,
// `127.0.0.1`, `::1` or `fe80::1%eth0`. An IPv6 literal is bracketed only once a port is attached
// to it (RFC 5952 section 6), which net.JoinHostPort does. A Sprintf'd `host:port` did not, so a
// listen host of `::` became `:::9090` and stopped both servers at start, and an IPv6 database host
// broke every connection string (#424).
//
// A host that arrives already in brackets, `[::1]`, is read as the same address. RFC 4038 section
// 5.1 asks that of anything parsing a literal address, and it keeps working the one spelling of an
// IPv6 listen or database host that the Sprintf'd form accepted.
package hostport

import (
	"net"
	"strconv"
)

// Join returns host and port as one address, bracketing an IPv6 literal. A host in one pair of
// enclosing brackets is unbracketed first, so `::1` and `[::1]` both give `[::1]:port` rather than
// the second giving `[[::1]]:port`, which Go refuses as missing its port. Anything else is passed
// through unrepaired, so a malformed host fails where it is used and names itself there.
func Join(host string, port int) string {
	return net.JoinHostPort(Unbracket(host), strconv.Itoa(port))
}

// Unbracket returns host without one pair of enclosing brackets, and any other host unchanged. It
// is the bracket rule net.SplitHostPort applies to `[host]:port`, for a host that has no port. A
// caller that uses a host on its own as well as in an address needs it: a TLS server name, an SMTP
// client's host and a comparison against a known address all take the bare form.
func Unbracket(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}
