package middleware

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
)

func TestMain(m *testing.M) {
	config.Init()
	os.Exit(m.Run())
}
