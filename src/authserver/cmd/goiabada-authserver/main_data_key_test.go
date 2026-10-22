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
	assert.Contains(t, refusal["remedy"], "the last key the stored data was encrypted under",
		"after a rotation, the key the database was set up with no longer opens it")
	messages := messagesOf(records)
	assert.NotContains(t, messages, "unable to create the database connection", "nor reported as a connection failure")
	assert.NotContains(t, messages, "starting the http listener", "and it never listens")

	code, records = runMainSignalledAt(t, path, "starting the http listener")
	require.Equalf(t, 0, code, "the key the database was set up with still starts it\n%s", dump(records))
}

// TestMain_ThePublishedSampleKeyStopsTheStartBeforeTheDatabase is the refusal of the data key the
// Compose samples published (#501) at the process: a start under it exits 1 under a headline that
// names it, with the refusal's remedy in the record's error, and before the database is opened, so
// nothing is sealed under a key anyone can read.
func TestMain_ThePublishedSampleKeyStopsTheStartBeforeTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.db")

	published := append(append([]string{}, singleStepEnv...),
		"GOIABADA_AES_ENCRYPTION_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	code, records := runMainSignalledAtWith(t, path, "", published)

	require.Equalf(t, 1, code, "the published key stops the start\n%s", dump(records))
	refusal := recordNamed(records, "the data encryption key is missing, malformed or the published sample key, so the auth server cannot start: set GOIABADA_AES_ENCRYPTION_KEY, and back it up separately from the database because every encrypted secret and signing key is unrecoverable without it")
	require.NotNilf(t, refusal, "the refusal is its own record\n%s", dump(records))
	assert.Equal(t, "ERROR", refusal["level"])
	assert.Contains(t, refusal["error"], "GOIABADA_AES_ENCRYPTION_KEY is the sample key this repository published")
	assert.Contains(t, refusal["error"], "https://goiabada.dev/deploy/rotate-secrets/#the-aes-key")
	assert.Equal(t, "openssl rand -hex 32", refusal["generate_with"])
	assert.NoFileExists(t, path, "no database was opened")
	assert.NotContains(t, messagesOf(records), "starting the http listener", "and it never listens")
}
