package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// TestComposePage_HealthChecksSayWhatTheCommandReads: the Docker Compose page's health checks
// section names every variable `healthcheck` reads its listener from, since an automatic check is a
// process of its own and inherits none of the server's flags (#808 decision 3), and lists the exit
// codes the command answers as a running one shows them: healthy, unhealthy, and an argument
// given. A code the command answers that the page doesn't list, or one it lists that the command
// doesn't answer, fails here.
func TestComposePage_HealthChecksSayWhatTheCommandReads(t *testing.T) {
	const page, heading = "site/src/content/docs/deploy/docker-compose.mdx", "## Health checks"
	section, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), page, heading)
	require.NoError(t, err)

	for _, variable := range []string{
		healthcheckListeners.HTTPHost, healthcheckListeners.HTTPPort,
		healthcheckListeners.HTTPSHost, healthcheckListeners.HTTPSPort,
		healthcheckListeners.CertFile, healthcheckListeners.KeyFile,
	} {
		assert.Containsf(t, section, "`"+variable+"`", "%s: %s names %s, which healthcheck reads", page, heading, variable)
	}
	assert.Containsf(t, section, "flags", "%s: %s says an automatic check does not inherit the server's flags", page, heading)

	healthyStub := newHealthStub(t, "tcp4", false, healthy)
	unhealthyStub := newHealthStub(t, "tcp4", false, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	answered := map[int]bool{
		runHealthcheck(t, httpOnly("127.0.0.1", healthyStub.port()), "healthcheck").code:          true,
		runHealthcheck(t, httpOnly("127.0.0.1", unhealthyStub.port()), "healthcheck").code:        true,
		runHealthcheck(t, httpOnly("127.0.0.1", healthyStub.port()), "healthcheck", "--now").code: true,
	}
	require.Len(t, answered, 3, "healthy, unhealthy and an argument given answer three codes")

	listed := map[int]bool{}
	for _, match := range regexp.MustCompile("(?m)^- `(\\d+)`").FindAllStringSubmatch(section, -1) {
		var code int
		_, _ = fmt.Sscan(match[1], &code)
		listed[code] = true
	}
	assert.Equalf(t, answered, listed, "%s: %s lists the exit codes healthcheck answers, each as a bullet", page, heading)
}
