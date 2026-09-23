package handlerhelpers

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

// The error page's last-resort body is catalog text, so the rows that read it need the catalog the
// running server loads at startup; without it every key renders as itself.
func TestMain(m *testing.M) {
	if _, err := i18n.LoadBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n.LoadBundle in TestMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
