package handlers

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	config.Init()
	// The catalogs, so a sentence the console writes itself (the session-ended answer) is read
	// in English rather than as its key.
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}
