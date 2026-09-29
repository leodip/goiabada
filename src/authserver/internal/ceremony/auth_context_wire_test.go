package ceremony

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two literals below are what AuthContext serialized to while this type lived in
// core/oauthprovider, captured from that tree before #339 moved it. They are the wire format of an
// in-flight ceremony: handlerhelpers.SaveAuthContext marshals this struct to JSON and puts the
// string in the session, so a ceremony that began on the old binary is decoded by the new one, and
// the field names below are the whole of the contract between them. AuthContext carries no json
// tags, so every field serializes under its Go name and renaming one is a silent break.
//
// Both predate RequestedScope (#436), so they are now the decode side only: what a ceremony in
// flight across that deploy carries. RequestedScope decodes from them as "", and re-encoding
// appends the key, which the Reencoded literals pin.
const populatedAuthContextJSON = `{"ClientId":"client-one","RedirectURI":"https://rp.example/cb","ResponseType":"code","CodeChallengeMethod":"S256","CodeChallenge":"challenge","ResponseMode":"query","Scope":"openid profile","ConsentedScope":"openid","MaxAge":"300","AcrValuesFromAuthorizeRequest":"urn:goiabada:level2_optional","State":"state-value","Nonce":"nonce-value","UserAgent":"probe/1.0","IpAddress":"203.0.113.7","AcrLevel":"urn:goiabada:level1","AuthMethods":"pwd otp","UserId":42,"AuthState":"ready_to_issue_code","Prompt":"consent","AuthenticatedAt":"2026-09-15T12:34:56Z","IdTokenHintSub":"sub-value","Level1AuthCompleted":true,"AuthStateGeneration":3,"OtpConfigGeneration":7,"OTPKeyURL":"otpauth://totp/x","CeremonyId":"ceremony-1","UILocales":["pt-BR","en"],"DeferredErrorCode":"invalid_scope","DeferredErrorDescription":"bad scope","TargetAcrLevel":"urn:goiabada:level2_mandatory"}`

// No field carries omitempty, so every key is present even on a zero value. That is what makes
// the zero literal worth its place: a json tag added to any field shows up here, where the
// populated literal alone could be satisfied by a tag whose name happened to match.
const zeroAuthContextJSON = `{"ClientId":"","RedirectURI":"","ResponseType":"","CodeChallengeMethod":"","CodeChallenge":"","ResponseMode":"","Scope":"","ConsentedScope":"","MaxAge":"","AcrValuesFromAuthorizeRequest":"","State":"","Nonce":"","UserAgent":"","IpAddress":"","AcrLevel":"","AuthMethods":"","UserId":0,"AuthState":"","Prompt":"","AuthenticatedAt":null,"IdTokenHintSub":"","Level1AuthCompleted":false,"AuthStateGeneration":0,"OtpConfigGeneration":null,"OTPKeyURL":"","CeremonyId":"","UILocales":null,"DeferredErrorCode":"","DeferredErrorDescription":"","TargetAcrLevel":""}`

// The two literals above as this binary writes them back: identical but for the RequestedScope key
// appended last, which is where the struct declares it. A key anywhere else would mean a field had
// moved.
const populatedAuthContextJSONReencoded = `{"ClientId":"client-one","RedirectURI":"https://rp.example/cb","ResponseType":"code","CodeChallengeMethod":"S256","CodeChallenge":"challenge","ResponseMode":"query","Scope":"openid profile","ConsentedScope":"openid","MaxAge":"300","AcrValuesFromAuthorizeRequest":"urn:goiabada:level2_optional","State":"state-value","Nonce":"nonce-value","UserAgent":"probe/1.0","IpAddress":"203.0.113.7","AcrLevel":"urn:goiabada:level1","AuthMethods":"pwd otp","UserId":42,"AuthState":"ready_to_issue_code","Prompt":"consent","AuthenticatedAt":"2026-09-15T12:34:56Z","IdTokenHintSub":"sub-value","Level1AuthCompleted":true,"AuthStateGeneration":3,"OtpConfigGeneration":7,"OTPKeyURL":"otpauth://totp/x","CeremonyId":"ceremony-1","UILocales":["pt-BR","en"],"DeferredErrorCode":"invalid_scope","DeferredErrorDescription":"bad scope","TargetAcrLevel":"urn:goiabada:level2_mandatory","RequestedScope":""}`

const zeroAuthContextJSONReencoded = `{"ClientId":"","RedirectURI":"","ResponseType":"","CodeChallengeMethod":"","CodeChallenge":"","ResponseMode":"","Scope":"","ConsentedScope":"","MaxAge":"","AcrValuesFromAuthorizeRequest":"","State":"","Nonce":"","UserAgent":"","IpAddress":"","AcrLevel":"","AuthMethods":"","UserId":0,"AuthState":"","Prompt":"","AuthenticatedAt":null,"IdTokenHintSub":"","Level1AuthCompleted":false,"AuthStateGeneration":0,"OtpConfigGeneration":null,"OTPKeyURL":"","CeremonyId":"","UILocales":null,"DeferredErrorCode":"","DeferredErrorDescription":"","TargetAcrLevel":"","RequestedScope":""}`

// A ceremony written by this binary, with RequestedScope set, which is the shape every context
// minted after #436 carries.
const requestedScopeAuthContextJSON = `{"ClientId":"client-one","RedirectURI":"https://rp.example/cb","ResponseType":"code","CodeChallengeMethod":"S256","CodeChallenge":"challenge","ResponseMode":"query","Scope":"openid profile","ConsentedScope":"openid","MaxAge":"300","AcrValuesFromAuthorizeRequest":"urn:goiabada:level2_optional","State":"state-value","Nonce":"nonce-value","UserAgent":"probe/1.0","IpAddress":"203.0.113.7","AcrLevel":"urn:goiabada:level1","AuthMethods":"pwd otp","UserId":42,"AuthState":"ready_to_issue_code","Prompt":"consent","AuthenticatedAt":"2026-09-15T12:34:56Z","IdTokenHintSub":"sub-value","Level1AuthCompleted":true,"AuthStateGeneration":3,"OtpConfigGeneration":7,"OTPKeyURL":"otpauth://totp/x","CeremonyId":"ceremony-1","UILocales":["pt-BR","en"],"DeferredErrorCode":"invalid_scope","DeferredErrorDescription":"bad scope","TargetAcrLevel":"urn:goiabada:level2_mandatory","RequestedScope":"openid profile email"}`

// populatedAuthContext is the value populatedAuthContextJSON decodes to.
func populatedAuthContext() AuthContext {
	authenticatedAt := time.Date(2026, 9, 15, 12, 34, 56, 0, time.UTC)
	otpConfigGeneration := int64(7)
	return AuthContext{
		ClientId:                      "client-one",
		RedirectURI:                   "https://rp.example/cb",
		ResponseType:                  "code",
		CodeChallengeMethod:           "S256",
		CodeChallenge:                 "challenge",
		ResponseMode:                  "query",
		Scope:                         "openid profile",
		ConsentedScope:                "openid",
		MaxAge:                        "300",
		AcrValuesFromAuthorizeRequest: "urn:goiabada:level2_optional",
		State:                         "state-value",
		Nonce:                         "nonce-value",
		UserAgent:                     "probe/1.0",
		IpAddress:                     "203.0.113.7",
		AcrLevel:                      "urn:goiabada:level1",
		AuthMethods:                   "pwd otp",
		UserId:                        42,
		AuthState:                     AuthStateReadyToIssueCode,
		Prompt:                        "consent",
		AuthenticatedAt:               &authenticatedAt,
		IdTokenHintSub:                "sub-value",
		Level1AuthCompleted:           true,
		AuthStateGeneration:           3,
		OtpConfigGeneration:           &otpConfigGeneration,
		OTPKeyURL:                     "otpauth://totp/x",
		CeremonyId:                    "ceremony-1",
		UILocales:                     []string{"pt-BR", "en"},
		DeferredErrorCode:             "invalid_scope",
		DeferredErrorDescription:      "bad scope",
		TargetAcrLevel:                "urn:goiabada:level2_mandatory",
	}
}

// TestAuthContextWire_PopulatedRoundTrip decodes a pre-move ceremony and re-encodes it, and both
// halves are load-bearing. encoding/json discards a key with no matching field, so decoding alone
// still passes after a field is deleted -- which is precisely the value a ceremony in flight across
// a deployment would lose. Encoding alone still passes after a field is added.
func TestAuthContextWire_PopulatedRoundTrip(t *testing.T) {
	var got AuthContext
	require.NoError(t, json.Unmarshal([]byte(populatedAuthContextJSON), &got))
	assert.Equal(t, populatedAuthContext(), got)

	encoded, err := json.Marshal(&got)
	require.NoError(t, err)
	assert.Equal(t, populatedAuthContextJSONReencoded, string(encoded))
}

func TestAuthContextWire_ZeroRoundTrip(t *testing.T) {
	var got AuthContext
	require.NoError(t, json.Unmarshal([]byte(zeroAuthContextJSON), &got))
	assert.Equal(t, AuthContext{}, got)

	encoded, err := json.Marshal(&got)
	require.NoError(t, err)
	assert.Equal(t, zeroAuthContextJSONReencoded, string(encoded))
}

// TestAuthContextWire_RequestedScopeRoundTrip is the new format in both directions: the key
// decodes into RequestedScope and nothing else, and the value encodes back byte for byte.
func TestAuthContextWire_RequestedScopeRoundTrip(t *testing.T) {
	want := populatedAuthContext()
	want.RequestedScope = "openid profile email"

	var got AuthContext
	require.NoError(t, json.Unmarshal([]byte(requestedScopeAuthContextJSON), &got))
	assert.Equal(t, want, got)

	encoded, err := json.Marshal(&got)
	require.NoError(t, err)
	assert.Equal(t, requestedScopeAuthContextJSON, string(encoded))
}
