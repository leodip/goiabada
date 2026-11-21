package guard

import (
	"fmt"
	"os"
	"testing"
)

// TestMain runs the package's tests, then removes what they built for the whole run: the checker
// the screenshot command's tests share.
func TestMain(m *testing.M) {
	code := m.Run()
	if err := removeScreenshotCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "removing the screenshotcheck build: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
