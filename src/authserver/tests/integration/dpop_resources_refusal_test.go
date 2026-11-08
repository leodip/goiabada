package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// A request the resource's handler refuses leaves its DPoP proof unspent, through the running
// server and its replay table (#42 decision 9): a refusal by the handler's own checks, of the
// session or of a credential, leaves no record of the proof, and the same proof is admitted once
// the request is corrected, and only once.

// sendJSONWithProof sends body as JSON to the auth server's path with token in the DPoP scheme and
// proof beside it.
func sendJSONWithProof(t *testing.T, method, path, token, proof string, body any) resourceAnswer {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, resourceURL(path), strings.NewReader(string(raw)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	answer := resourceAnswer{status: resp.StatusCode, challenge: resp.Header.Values("WWW-Authenticate"), header: resp.Header}
	raw, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &answer.body), "status %d: %s", resp.StatusCode, raw)
	}
	return answer
}

// proofRecords counts the replay table's records of proof sent to path, read straight from the
// table: the key is RFC 9449's htu and the proof's own jti, hashed as decision 9 says, the SHA-256
// of the two joined by a space. The key is a hex digest, so it is inlined, which every engine reads.
func proofRecords(t *testing.T, path, proof string) int {
	t.Helper()
	claimsJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[1])
	require.NoError(t, err)
	var claims struct {
		JTI string `json:"jti"`
	}
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	require.NotEmpty(t, claims.JTI)
	sum := sha256.Sum256([]byte(resourceURL(path) + " " + claims.JTI))
	var count int
	require.NoError(t, database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), fmt.Sprintf(
			"SELECT COUNT(*) FROM dpop_proofs WHERE proof_hash = '%s'", hex.EncodeToString(sum[:]))).Scan(&count)
	}))
	return count
}

// The logout request needs the token's session, which a password grant token has none of: the
// handler refuses it 401 INVALID_SESSION, in the DPoP scheme the request used, and records nothing.
func TestDPoPResources_AHandlersSessionRefusalLeavesTheProofUnspent(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.boundToken(t, key)
	require.NotContains(t, decodeJWTPayload(t, token), "sid", "a password grant token has no session")
	const path = "/api/v1/account/logout-request"
	const redirect = "https://client.example.com/dpop-signed-out"
	require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil,
		&record.PostLogoutRedirectURI{ClientId: u.client.Id, URI: redirect}))
	proof := key.ResourceProof(t, http.MethodPost, resourceURL(path), time.Now(), token)

	refused := sendJSONWithProof(t, http.MethodPost, path, token, proof, api.AccountLogoutRequest{
		ClientIdentifier: u.client.ClientIdentifier, PostLogoutRedirectUri: redirect,
	})

	require.Equal(t, http.StatusUnauthorized, refused.status, "%v", refused.body)
	assert.Equal(t, "INVALID_SESSION", refused.body["error_code"])
	require.Len(t, refused.challenge, 1)
	assert.Contains(t, refused.challenge[0], dpopChallengeBare)
	assert.Equal(t, 0, proofRecords(t, path, proof), "the refused request left no record of its proof")
}

// A wrong current password is refused 400 AUTHENTICATION_FAILED by the handler, and records
// nothing; the same proof with the right password changes it, and that request spends the proof.
// (The change revokes the token, so the replay of a spent proof is shown on userinfo, in
// TestDPoPResources_AReplayedProofIsRefused.)
func TestDPoPResources_AHandlersCredentialRefusalLeavesTheProofForTheCorrectedRequest(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.boundToken(t, key)
	const path = "/api/v1/account/password"
	proof := key.ResourceProof(t, http.MethodPut, resourceURL(path), time.Now(), token)
	body := api.UpdateAccountPasswordRequest{CurrentPassword: "not-the-current-password", NewPassword: "An0ther-long-DPoP-passphrase!x41"}

	refused := sendJSONWithProof(t, http.MethodPut, path, token, proof, body)
	require.Equal(t, http.StatusBadRequest, refused.status, "%v", refused.body)
	assert.Equal(t, "AUTHENTICATION_FAILED", refused.body["error_code"])
	assert.Equal(t, 0, proofRecords(t, path, proof), "the refused request left no record of its proof")

	body.CurrentPassword = u.password
	corrected := sendJSONWithProof(t, http.MethodPut, path, token, proof, body)
	require.Equal(t, http.StatusOK, corrected.status, "the unspent proof is admitted with the request corrected: %v", corrected.body)
	assert.Equal(t, 1, proofRecords(t, path, proof), "the request that succeeded spent the proof")
}
