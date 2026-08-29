package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBootstrapEnvContent_CarriesNoClientId pins the whole point of #285 on the one artifact that
// hands an operator their configuration: the admin console's client id is not configurable, so the
// bootstrap file must not offer it as something to copy. Nothing else reaches this file, which is
// built inside Seed and would otherwise need a live database to observe.
func TestBootstrapEnvContent_CarriesNoClientId(t *testing.T) {
	content := bootstrapEnvContent("the-secret", "aaaa", "bbbb", "cccc", "dddd")

	assert.NotContains(t, content, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID",
		"the bootstrap file must not name a variable the admin console no longer reads")
	assert.NotContains(t, content, "admin-console-client",
		"nor the value under any other name")
}

// TestBootstrapEnvContent_CarriesEveryRemainingCredential is the other half: removing the client id
// must not have taken a neighbour with it. Each remaining variable is asserted with its value, so a
// line that survives with the wrong argument bound to it fails here rather than at an operator's
// first restart.
func TestBootstrapEnvContent_CarriesEveryRemainingCredential(t *testing.T) {
	content := bootstrapEnvContent("the-secret", "auth-key", "enc-key", "ac-auth-key", "ac-enc-key")

	expected := []string{
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=the-secret",
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=auth-key",
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=enc-key",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=ac-auth-key",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=ac-enc-key",
	}
	for _, line := range expected {
		assert.Contains(t, content, line)
	}

	// Five assignments and no sixth: an added variable has to be considered here rather than
	// arriving silently, since this file is copied by hand into a deployment.
	assignments := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "GOIABADA_") {
			assignments++
		}
	}
	assert.Equal(t, len(expected), assignments)
}
