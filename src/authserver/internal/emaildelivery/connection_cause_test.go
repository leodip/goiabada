package emaildelivery

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dialOpError is the shape net.Dial wraps every failure in: the operation, the address and, inside,
// the cause.
func dialOpError(cause error) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 587},
		Err:  cause,
	}
}

// The cause is read from the error's type, on errors built the way the dial builds them, rather than
// on live DNS or a black-holed address, whose behaviour differs between machines (#410 decision 4).
func TestClassifyConnectionError(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", Name: "smtp.example.invalid", IsNotFound: true}

	testCases := []struct {
		name string
		err  error
		want ConnectionCause
	}{
		{"a host name not found", notFound, ConnectionCauseHostNotFound},
		{"a host name not found, as the dial wraps it", dialOpError(notFound), ConnectionCauseHostNotFound},
		// A name the resolver could not answer for is a DNS failure too, whatever stopped it: the
		// administrator's next step is the host name either way.
		{"a resolver that timed out", &net.DNSError{Err: "i/o timeout", Name: "smtp.example.test", IsTimeout: true},
			ConnectionCauseHostNotFound},
		{"a resolver that failed", &net.DNSError{Err: "server misbehaving", Name: "smtp.example.test", IsTemporary: true},
			ConnectionCauseHostNotFound},
		{"a dial that timed out", dialOpError(os.ErrDeadlineExceeded), ConnectionCauseTimedOut},
		{"a context deadline", context.DeadlineExceeded, ConnectionCauseTimedOut},
		{"a refused connection", dialOpError(&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}),
			ConnectionCauseRefused},
		// Wrapped by this tree on the way up, as a sender failing past the dial would: the chain is
		// walked, not only its outermost error.
		{"a refused connection, wrapped",
			errs.Wrap(dialOpError(&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}), "unable to dial"),
			ConnectionCauseRefused},
		{"an unreachable network", dialOpError(&os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH}),
			ConnectionCauseNone},
		// The text names a refusal and a timeout; the type names neither.
		{"an error whose text only reads like a cause", errs.New("connection refused: i/o timeout: no such host"),
			ConnectionCauseNone},
		{"no error", nil, ConnectionCauseNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ClassifyConnectionError(tc.err))
		})
	}
}

// A real dial to a loopback port nothing listens on is read as refused: the constructed refusal
// above is the shape the dial actually returns.
func TestClassifyConnectionError_ARefusedLoopbackPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	_, err = net.DialTimeout("tcp", address, 3*time.Second)
	require.Error(t, err)

	assert.Equal(t, ConnectionCauseRefused, ClassifyConnectionError(err))
}
