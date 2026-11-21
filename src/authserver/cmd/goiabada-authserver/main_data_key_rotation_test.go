package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/core/builtin"
)

// TestMain_TheDataKeyRotatesThroughOrdinaryRestarts is the walk of #492 decision 9: one SQLite
// file, and a real auth server started with each step's variables of the documented rotation in
// turn. Each one serves a client-credentials token, which opens the admin console client's secret
// and the current signing key through the server's data cipher, and reencrypt runs through the
// real main between the swap and the removal of the previous key. It is what fails if main drops
// the previous key on its way to the cipher, or if the documented order stops working; the data
// tier proves the same phases on every engine, through a cipher it builds itself.
func TestMain_TheDataKeyRotatesThroughOrdinaryRestarts(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x3c}, 32)
	newKey := bytes.Repeat([]byte{0xc3}, 32)
	path := filepath.Join(t.TempDir(), "rotation.db")
	current := func(key []byte) string { return "GOIABADA_AES_ENCRYPTION_KEY=" + hex.EncodeToString(key) }
	previous := func(key []byte) string { return "GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS=" + hex.EncodeToString(key) }

	records := serveOneToken(t, path, current(oldKey))
	assert.Equal(t, 0, count(messagesOf(records), stillUnderPreviousRecord), "the first start seeds under the old key")
	assertStoredUnder(t, path, oldKey)

	// Step 1, on Kubernetes: the new key goes in as the previous key, and every server still seals
	// under the old one.
	records = serveOneToken(t, path, current(oldKey), previous(newKey))
	assert.Equal(t, 0, count(messagesOf(records), stillUnderPreviousRecord),
		"the data is under the current key, so there is nothing to warn of\n%s", dump(records))

	// Step 2: the swap. The stored secrets are under the old key, now the previous one, and the
	// server still opens them.
	records = serveOneToken(t, path, current(newKey), previous(oldKey))
	assert.Equal(t, 1, count(messagesOf(records), stillUnderPreviousRecord),
		"the start says the data is still under the previous key\n%s", dump(records))
	assertStoredUnder(t, path, oldKey)

	// The previous key removed before reencrypt has run is refused.
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	refused := startMainChild(t, ctx, []string{
		"GOIABADA_DB_DSN=file:" + path, current(newKey),
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=" + strconv.Itoa(freePort(t)),
	})
	code, records := refused.wait(t, ctx)
	require.Equalf(t, 1, code, "a start with the previous key removed too soon is refused\n%s", dump(records))
	assert.NotNil(t, recordNamed(records, "the data encryption key does not decrypt the stored data, so the auth server cannot start"),
		"\n%s", dump(records))

	// Step 3: reencrypt, beside where the servers would go on serving.
	code, stderr := runMainProcessWith(t, filepath.Join(t.TempDir(), "decoy.db"),
		[]string{current(newKey), previous(oldKey)}, "reencrypt", "--db-dsn=file:"+path)
	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
	assertStoredUnder(t, path, newKey)

	// Step 4: the previous key removed.
	records = serveOneToken(t, path, current(newKey))
	assert.Equal(t, 0, count(messagesOf(records), stillUnderPreviousRecord), "\n%s", dump(records))
}

// serveOneToken starts main over the SQLite file at path with keys, asks it for one
// client-credentials token as the admin console's client, stops it with SIGTERM, and answers its
// records. The token is the proof that the server opened the client secret and the current
// signing key with the keys it was given.
func serveOneToken(t *testing.T, path string, keys ...string) []map[string]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	port := strconv.Itoa(freePort(t))
	child := startMainChild(t, ctx, append([]string{
		"GOIABADA_DB_DSN=file:" + path,
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=" + port,
	}, keys...))
	base := "http://127.0.0.1:" + port

	status, _, body := getWhenUp(t, ctx, base+"/health")
	require.Equal(t, http.StatusOK, status, body)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/auth/token", strings.NewReader(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {builtin.AdminConsoleClientIdentifier},
		"client_secret": {adminConsoleClientSecret(t)},
		"scope":         {builtin.AuthServerResourceIdentifier + ":" + builtin.BrowserSessionsPermissionIdentifier},
	}.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	answer, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.NoError(t, err)

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, records := child.wait(t, ctx)
	require.Equalf(t, http.StatusOK, response.StatusCode, "the token request with %v: %s\n%s", keyNames(keys), answer, dump(records))
	var token map[string]any
	require.NoError(t, json.Unmarshal(answer, &token))
	assert.NotEmpty(t, token["access_token"], "a signed access token")
	require.Equalf(t, 0, code, "a drained stop exits 0\n%s", dump(records))
	return records
}

// adminConsoleClientSecret is the admin console client's secret the single-step seed stores.
func adminConsoleClientSecret(t *testing.T) string {
	t.Helper()
	for _, variable := range singleStepEnv {
		if value, found := strings.CutPrefix(variable, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="); found {
			return value
		}
	}
	t.Fatal("the single-step configuration names no admin console client secret")
	return ""
}

// keyNames is the data-key variables a step sets, without their values, for a failure message.
func keyNames(keys []string) []string {
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		name, _, _ := strings.Cut(k, "=")
		names = append(names, name)
	}
	return names
}

// assertStoredUnder holds the client secret and every signing key in the SQLite file at path to
// key, opened with key alone and not by the code under test.
func assertStoredUnder(t *testing.T, path string, key []byte) {
	t.Helper()

	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()

	client, err := db.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	secret, err := encryption.DecryptText(client.ClientSecretEncrypted, key)
	require.NoError(t, err, "the client secret is under the key expected")
	assert.Equal(t, adminConsoleClientSecret(t), secret)

	signingKeys, err := db.GetAllSigningKeys(context.Background(), nil)
	require.NoError(t, err)
	require.NotEmpty(t, signingKeys)
	for _, signingKey := range signingKeys {
		_, openErr := encryption.DecryptText(signingKey.PrivateKeyPEM, key)
		assert.NoErrorf(t, openErr, "the %s signing key is under the key expected", signingKey.State)
	}
}
