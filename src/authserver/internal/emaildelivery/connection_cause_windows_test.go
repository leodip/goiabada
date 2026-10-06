package emaildelivery

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Winsock reports a refused connection as WSAECONNREFUSED inside the error ConnectEx returns, which
// is the shape built here; TestClassifyConnectionError_ARefusedLoopbackPort is the real dial.
func TestClassifyConnectionError_AWinsockRefusal(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 587},
		Err: &os.SyscallError{Syscall: "connectex", Err: syscall.Errno(10061)}}

	assert.Equal(t, ConnectionCauseRefused, ClassifyConnectionError(err))
}
