package integration

import (
	"context"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 6 for the revoked-family record (#132, #259, #437), over HTTP against the running server. A
// rotation that races a revocation of its family can commit a live child into a family the sweep
// already ran over, and the record the revocation left behind is what refuses that child when it is
// presented. The interleaving itself is the data tier's, on each engine; this is the sequential
// shape a client can observe: the record refuses a live token the sweep did not revoke, and a
// replay's containment writes the record.

const familyRecordReplayDescription = "The refresh token is invalid."

func requireRefusedAsAnInvalidRefreshToken(t *testing.T, status int, body map[string]interface{}, what string) {
	t.Helper()

	assertRefusedAsInvalidGrant(t, status, body, what)
	assert.Equalf(t, familyRecordReplayDescription, body["error_description"],
		"%s says nothing about why: a family's record is not something a client can act on", what)
}

// A child born live into a recorded family is refused at presentation, and its row is left as it is:
// the validator refuses before any claim, so the token is not spent. The state is what a rotation
// that committed between a revocation's read and its commit leaves behind, built here by recording
// the family directly over a live child.
func TestToken_Refresh_ARecordedFamilyRefusesALiveChild(t *testing.T) {
	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	rt1 := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
		code.Code, code.RedirectURI, testCodeVerifier)
	rt2 := rotateRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	child := refreshTokenRowByJti(t, rt2)
	require.False(t, child.Revoked, "the child starts out live")

	// The control: before the record exists the live child rotates, which is what makes the refusal
	// below the record's and not something the child trips anyway.
	written, err := database.RecordRefreshTokenFamilyRevoked(context.Background(), nil, child.FirstRefreshTokenJti, "test_family_record")
	require.NoError(t, err)
	require.True(t, written)

	status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt2)
	requireRefusedAsAnInvalidRefreshToken(t, status, body, "a live child of a recorded family")

	assert.False(t, refreshTokenRowByJti(t, rt2).Revoked,
		"the refusal came before any claim, so the child was not spent")
	rows, err := database.GetRefreshTokensByCodeId(context.Background(), nil, code.Id)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "no row was inserted by the refused refresh")
}

// The same for a password grant's family, which has no code: the record is keyed by the family's
// first jti, which every shape stamps.
func TestToken_Refresh_ARecordedFamilyRefusesALiveROPCChild(t *testing.T) {
	changeSettings(t, func(settings *models.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })

	clientSecret := fake.Password(32)
	password := fake.Password(12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)

	httpClient := createHttpClient(t)
	data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})
	require.NotNil(t, data["refresh_token"], "the ROPC grant must return a refresh token")
	rt1 := data["refresh_token"].(string)
	rt2 := rotateRefreshToken(t, httpClient, client.ClientIdentifier, clientSecret, rt1)
	child := refreshTokenRowByJti(t, rt2)
	require.False(t, child.CodeId.Valid, "a ROPC child has no code behind it")

	written, err := database.RecordRefreshTokenFamilyRevoked(context.Background(), nil, child.FirstRefreshTokenJti, "test_family_record")
	require.NoError(t, err)
	require.True(t, written)

	status, body := replayRefreshToken(t, httpClient, client.ClientIdentifier, clientSecret, rt2)
	requireRefusedAsAnInvalidRefreshToken(t, status, body, "a live ROPC child of a recorded family")

	assert.False(t, refreshTokenRowByJti(t, rt2).Revoked, "the refusal came before any claim")
}

// A replay's containment writes the family's record, and a repeated replay is answered as before:
// the retired token's own row is revoked, so the record is not what answers it, and the redemption
// contains nothing more. Both are invalid_grant 400 with the revoked-token wording, and the repeat
// writes no second record or audit event, which is what stops a client amplifying the log by
// presenting the same token repeatedly (#128, #132).
func TestToken_Refresh_AReplayRecordsTheFamilyAndARepeatStillAnswersAsRevoked(t *testing.T) {
	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	rt1 := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
		code.Code, code.RedirectURI, testCodeVerifier)
	rt2 := rotateRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	first := refreshTokenRowByJti(t, rt1).FirstRefreshTokenJti

	recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, first)
	require.NoError(t, err)
	require.False(t, recorded, "a family that was only rotated is not recorded")

	// The first replay is the containment: the retired parent reaches the issuer, which records the
	// family and revokes the live successor. Its answer is the revoked-token wording.
	status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "the first replay")
	assert.Equal(t, "This refresh token has been revoked.", body["error_description"])

	recorded, err = database.IsRefreshTokenFamilyRevoked(context.Background(), nil, first)
	require.NoError(t, err)
	assert.True(t, recorded, "the containment wrote the family's record")
	assert.True(t, refreshTokenRowByJti(t, rt2).Revoked, "and revoked the live successor")

	// Every later presentation of the family, the retired parent or the contained successor, is a
	// revoked row and is answered as one.
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "a repeated replay")
	assert.Equal(t, "This refresh token has been revoked.", body["error_description"])
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt2)
	assertRefusedAsInvalidGrant(t, status, body, "the contained successor")
	assert.Equal(t, "This refresh token has been revoked.", body["error_description"])
}

// Another family of the same client is untouched by the record: it is keyed by the family's first
// jti, not by the client or the session, so containment of one grant does not cut off another
// (#128 decision 3).
func TestToken_Refresh_ARecordedFamilyLeavesOtherFamiliesRotating(t *testing.T) {
	secretA := fake.Password(32)
	httpClient, codeA := createAuthCode(t, secretA, "openid profile email")
	secretB := fake.Password(32)
	clientB, redirectB, rawCodeB := codeOnSameSessionForNewClient(t, httpClient, secretB, "openid profile")

	rtA1 := exchangeAuthCode(t, httpClient, codeA.Client.ClientIdentifier, secretA,
		codeA.Code, codeA.RedirectURI, testCodeVerifier)
	rtB1 := exchangeAuthCode(t, httpClient, clientB.ClientIdentifier, secretB,
		rawCodeB, redirectB, testCodeVerifier+"-second-client")

	written, err := database.RecordRefreshTokenFamilyRevoked(context.Background(), nil,
		refreshTokenRowByJti(t, rtA1).FirstRefreshTokenJti, "test_family_record")
	require.NoError(t, err)
	require.True(t, written)

	status, body := replayRefreshToken(t, httpClient, codeA.Client.ClientIdentifier, secretA, rtA1)
	requireRefusedAsAnInvalidRefreshToken(t, status, body, "the recorded family's token")

	rtB2 := rotateRefreshToken(t, httpClient, clientB.ClientIdentifier, secretB, rtB1)
	assert.NotEqual(t, rtB1, rtB2, "the other family still rotates")
}
