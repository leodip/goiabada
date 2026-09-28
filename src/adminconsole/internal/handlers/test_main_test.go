package handlers

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/config"
)

func TestMain(m *testing.M) {
	if err := config.Init(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	code := m.Run()
	os.Exit(code)
}
