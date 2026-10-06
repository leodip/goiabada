//go:build windows

package emaildelivery

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is Winsock's WSAECONNREFUSED, which syscall does not declare. A refused dial on
// Windows carries it, inside the error ConnectEx returns, and syscall.ECONNREFUSED there is a value
// Go invents above APPLICATION_ERROR that Errno.Is does not equate with it.
const wsaeconnrefused syscall.Errno = 10061

// isConnectionRefused reports whether err is a refused connection, by its errno: Winsock's, or
// Go's own should anything return it.
func isConnectionRefused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}
