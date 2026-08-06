package apihandlers

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	config.Init()
	// The same fixed key the handlers and accounthandlers packages use. Without it every
	// models.SetOTPSecret in this package fails, so a handler that encrypts a secret returns 500
	// whatever else is wrong with it, and a test asserting 500 on an earlier branch passes even
	// when that branch is deleted (#111 stage 4).
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		fmt.Fprintf(os.Stderr, "encryption.InitDataCipher in TestMain: %v\n", err)
		os.Exit(1)
	}
	if _, err := i18n.LoadBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n.LoadBundle in TestMain: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}
