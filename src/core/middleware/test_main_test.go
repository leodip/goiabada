package middleware

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	// The CSRF middleware renders a localized error page, so without a loaded bundle
	// i18n.T falls back to echoing the key and the body assertions would pass against
	// the key rather than against the message.
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}
