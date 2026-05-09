package apihandlers

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	config.Init()
	if _, err := i18n.LoadBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n.LoadBundle in TestMain: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}
