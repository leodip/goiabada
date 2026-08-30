package server

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

// The middleware chain this package drives answers a refused request through
// i18n.T. Without a loaded bundle T echoes the key, and every body assertion here
// would pass against the key rather than against the message, which is exactly the
// state TestInitMiddleware_RefusalsAreLocalized exists to detect.
func TestMain(m *testing.M) {
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
