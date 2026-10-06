package emaildelivery

import (
	"errors"
	"net"
	"syscall"
)

// ConnectionCause is the coarse cause of a failed connection to an SMTP server, the one part of the
// failure an answer may name: it carries no address, port, resolver or operating-system string,
// which the error itself does (#410 decision 4).
type ConnectionCause int

const (
	// ConnectionCauseNone is every failure the other causes do not name, such as an unreachable
	// network.
	ConnectionCauseNone ConnectionCause = iota
	ConnectionCauseHostNotFound
	ConnectionCauseTimedOut
	ConnectionCauseRefused
)

// ClassifyConnectionError reads the cause of a failed connection from the error's type, never from
// its text (pattern 7), walking the whole chain. Any failure to resolve the host is a host name not
// found, a resolver that timed out included, since the host name is what to check either way; the
// DNS error is read first because it is a net.Error that can report a timeout too.
func ClassifyConnectionError(err error) ConnectionCause {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ConnectionCauseHostNotFound
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ConnectionCauseTimedOut
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ConnectionCauseRefused
	}
	return ConnectionCauseNone
}
