//go:build !windows

package emaildelivery

import (
	"errors"
	"syscall"
)

// isConnectionRefused reports whether err is a refused connection, by its errno.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
