package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain_AKeyThatDoesNotOpenTheStoredDataStopsTheStart is the data key check at the process
// (#542). A start under a key the database wasn't set up with used to go on and answer 500 from the
// first token request, "cipher: message authentication failed", while /health answered 200: on
// Kubernetes, a pod given newly generated Secrets by mistake replaced the working ones. Now it exits
// 1 before it listens, with a record that names the key and the remedy, and not the database
// connection error the failure used to be reported under.
func TestMain_AKeyThatDoesNotOpenTheStoredDataStopsTheStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.db")

	code, records := runMainSignalledAt(t, path, "starting the http listener")
	require.Equalf(t, 0, code, "the first start seeds the database under its key\n%s", dump(records))

	another := append(append([]string{}, singleStepEnv...), "GOIABADA_AES_ENCRYPTION_KEY="+strings.Repeat("cd", 32))
	code, records = runMainSignalledAtWith(t, path, "", another)

	require.Equalf(t, 1, code, "a key that opens none of the stored data stops the start\n%s", dump(records))
	refusal := recordNamed(records, "the data encryption key does not decrypt the stored data, so the auth server cannot start")
	require.NotNilf(t, refusal, "the refusal is its own record\n%s", dump(records))
	assert.Equal(t, "ERROR", refusal["level"])
	assert.Contains(t, refusal["remedy"], "GOIABADA_AES_ENCRYPTION_KEY")
	assert.Contains(t, refusal["remedy"], "backup")
	messages := messagesOf(records)
	assert.NotContains(t, messages, "unable to create the database connection", "nor reported as a connection failure")
	assert.NotContains(t, messages, "starting the http listener", "and it never listens")

	code, records = runMainSignalledAt(t, path, "starting the http listener")
	require.Equalf(t, 0, code, "the key the database was set up with still starts it\n%s", dump(records))
}
