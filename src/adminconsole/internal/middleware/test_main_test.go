package middleware

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

// Both of MiddlewareSettingsCache's refusals render through i18n.T, so without a
// loaded bundle T echoes the key and every body assertion in this package would
// pass against the key rather than against the message.
func TestMain(m *testing.M) {
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
