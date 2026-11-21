package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/encryption"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publishedSampleDataKey is the data key the Compose samples published (#501), which a start and
// the reencrypt command refuse as the current key. This file is one of those the literal stack
// secret guard lets name it, so the other command tests take it from here.
const publishedSampleDataKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

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
	assert.Contains(t, refusal["remedy"], "put GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS back, start, and run goiabada-authserver reencrypt",
		"a previous key removed before reencrypt reached its end is the mid-rotation case of the same refusal (#492 decision 6)")
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
		"GOIABADA_AES_ENCRYPTION_KEY="+publishedSampleDataKey)
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

// stillUnderPreviousRecord is the Warn record a start writes when the stored data is still under
// the previous data key (#492 decision 6).
const stillUnderPreviousRecord = "the stored data is still under the previous data encryption key: " +
	"run goiabada-authserver reencrypt before removing GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS"

// TestMain_AStartUnderThePreviousKeyServesAndSaysSo is the start between the swap and the end of
// reencrypt, at the process (#492 decision 6): the database is under the old key, which is now the
// previous one. The start serves, writes one Warn record naming the command that moves the data,
// and moves nothing itself (#492 decision 3): the signing key is still under the old key alone.
func TestMain_AStartUnderThePreviousKeyServesAndSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.db")
	oldKey := bytes.Repeat([]byte{0xab}, 32) // the key runMainSignalledAt seeds under

	code, records := runMainSignalledAt(t, path, "starting the http listener")
	require.Equalf(t, 0, code, "the first start seeds the database under its key\n%s", dump(records))
	assert.Nil(t, recordNamed(records, stillUnderPreviousRecord), "a start with one key warns of nothing")

	swapped := append(append([]string{}, singleStepEnv...),
		"GOIABADA_AES_ENCRYPTION_KEY="+strings.Repeat("cd", 32),
		"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS="+strings.Repeat("ab", 32))
	code, records = runMainSignalledAtWith(t, path, "starting the http listener", swapped)

	require.Equalf(t, 0, code, "the swapped keys start the server\n%s", dump(records))
	assert.Equal(t, 1, count(messagesOf(records), stillUnderPreviousRecord), "one record says so\n%s", dump(records))
	warned := recordNamed(records, stillUnderPreviousRecord)
	require.NotNil(t, warned)
	assert.Equal(t, "WARN", warned["level"])

	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()
	signingKey, err := db.GetCurrentSigningKey(context.Background(), nil)
	require.NoError(t, err)
	_, err = encryption.DecryptText(signingKey.PrivateKeyPEM, oldKey)
	assert.NoError(t, err, "the start re-encrypted nothing: the signing key is still under the old key")
}
