package protocolvalidation

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
)

// An authorization request's dpop_jkt binds the code it yields to one DPoP key (RFC 9449 section 10,
// #42 decision 14). At the authorization endpoint it is the SHA-256 JWK thumbprint of that key
// (RFC 7638), held to the one canonical validator an S256 challenge is held to (decision 20), and it
// is accepted only with a response type that returns a code. At the token endpoint a bound code is
// redeemed only with a proof by that key, and every other attempt is refused invalid_grant before
// the code is claimed, so it stays the key holder's to redeem.

const (
	dpopJktRefused = "The dpop_jkt parameter is incorrect. It must be the SHA-256 JWK thumbprint of the DPoP key (RFC 7638), " +
		"base64url-encoded without padding: 43 characters of A-Z, a-z, 0-9, '-' and '_'."
	dpopJktWithoutCode = "The dpop_jkt parameter binds the authorization code to a DPoP key, so it is accepted only with response_type=code."
	boundCodeRefused   = "The authorization code is bound to a DPoP key, and the request carries no proof by that key."
)

func TestValidateRequest_DPoPJktGrammar(t *testing.T) {
	validator := NewAuthorizeValidator(nil)
	request := func(jkt string) *ValidateRequestInput {
		return &ValidateRequestInput{
			AuthorizationCodeEnabled: true,
			ResponseType:             "code",
			CodeChallengeMethod:      "S256",
			CodeChallenge:            rfc7636Challenge,
			Scope:                    "openid",
			DPoPJkt:                  jkt,
		}
	}

	accepted := map[string]string{
		"RFC 7638's example thumbprint":                 rfc7638Thumbprint,
		"32 zero bytes":                                 strings.Repeat("A", 43),
		"32 bytes of ones":                              strings.Repeat("_", 42) + "8",
		"no dpop_jkt, which an empty value is too":      "",
		"a value that is also a real S256 challenge":    rfc7636Challenge,
		"a thumbprint with '-' and '_' and every class": "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
	}
	for name, jkt := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(request(jkt)))
		})
	}

	refused := map[string]string{
		// The thumbprint's last character, 's', is 101100; 't' and 'u' set one of the two spare bits each.
		"the lower spare bit set":                    with(rfc7638Thumbprint, 42, "t"),
		"the higher spare bit set":                   with(rfc7638Thumbprint, 42, "u"),
		"32 bytes of ones with a spare bit set":      strings.Repeat("_", 43),
		"padding appended":                           rfc7638Thumbprint + "=",
		"padding in the last place":                  with(rfc7638Thumbprint, 42, "="),
		"42 characters":                              rfc7638Thumbprint[:42],
		"44 characters":                              rfc7638Thumbprint + "A",
		"128 characters of the base64url alphabet":   strings.Repeat("A", 128),
		"a period":                                   with(rfc7638Thumbprint, 10, "."),
		"a tilde":                                    with(rfc7638Thumbprint, 10, "~"),
		"a plus":                                     with(rfc7638Thumbprint, 10, "+"),
		"a slash":                                    with(rfc7638Thumbprint, 10, "/"),
		"a CR in place of the first character":       with(rfc7638Thumbprint, 0, "\r"),
		"an LF in place of a middle character":       with(rfc7638Thumbprint, 21, "\n"),
		"a space in place of the last character":     with(rfc7638Thumbprint, 42, " "),
		"a tab in place of a middle character":       with(rfc7638Thumbprint, 21, "\t"),
		"a CR and an LF added at the end":            rfc7638Thumbprint + "\r\n",
		"an LF added in the middle":                  rfc7638Thumbprint[:21] + "\n" + rfc7638Thumbprint[21:],
		"a space added at the start":                 " " + rfc7638Thumbprint,
		"a two-byte character":                       rfc7638Thumbprint[:41] + "é",
		"a SHA-1 thumbprint's length, 27 characters": rfc7638Thumbprint[:27],
	}
	for name, jkt := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			err := validator.ValidateRequest(request(jkt))

			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
			assert.Equal(t, dpopJktRefused, detail.Description())
		})
	}

	// It stays optional whatever the client: a client requiring DPoP, or one that must use PKCE, is
	// not refused for leaving it out, and a code request without PKCE may carry it.
	t.Run("is optional for a client requiring DPoP and PKCE", func(t *testing.T) {
		input := request("")
		input.DPoPBoundAccessTokens = true
		input.PKCERequired = true
		assert.NoError(t, validator.ValidateRequest(input))
	})
	t.Run("is accepted without PKCE", func(t *testing.T) {
		assert.NoError(t, validator.ValidateRequest(&ValidateRequestInput{
			AuthorizationCodeEnabled: true, ResponseType: "code", Scope: "openid", DPoPJkt: rfc7638Thumbprint,
		}))
	})
}

// With a response type that returns no code nothing could be bound, so the request is refused
// invalid_request, whatever the value.
func TestValidateRequest_DPoPJktNeedsAResponseTypeThatReturnsACode(t *testing.T) {
	validator := NewAuthorizeValidator(nil)
	for _, responseType := range []string{"token", "id_token", "id_token token", "token id_token"} {
		for _, jkt := range []string{rfc7638Thumbprint, "not-a-thumbprint"} {
			t.Run(responseType+" with "+jkt, func(t *testing.T) {
				err := validator.ValidateRequest(&ValidateRequestInput{
					ResponseType:             responseType,
					AuthorizationCodeEnabled: true,
					ImplicitGrantEnabled:     true,
					Scope:                    "openid",
					Nonce:                    "the-nonce",
					DPoPJkt:                  jkt,
				})

				var detail *oauth.ErrorDetail
				require.ErrorAs(t, err, &detail)
				assert.Equal(t, "invalid_request", detail.Code())
				assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
				assert.Equal(t, dpopJktWithoutCode, detail.Description())
			})
		}
		t.Run(responseType+" without dpop_jkt is answered as before", func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(&ValidateRequestInput{
				ResponseType: responseType, AuthorizationCodeEnabled: true, ImplicitGrantEnabled: true,
				Scope: "openid", Nonce: "the-nonce",
			}))
		})
	}
}

// A code bound to a key is redeemed only with a proof by that key. Every attempt the binding refuses
// is invalid_grant with a Warn record, answered above the reuse return, so a used bound code
// presented without its key never reaches #77's containment, and before the issuer claims anything.
// The binding passes on every other row, which then meets a disabled user, the first check below
// the reuse return, so the binding is shown to sit above it and above every check of the account.
func TestValidateTokenRequest_CodeGrant_ABoundCodeNeedsAProofByItsKey(t *testing.T) {
	const redirectURI = "https://example.com/callback"

	bindingRefusal := &wantRefusal{code: "invalid_grant", description: boundCodeRefused, status: http.StatusBadRequest}
	disabledUser := &wantRefusal{code: "invalid_grant", description: "Code is invalid.", status: http.StatusBadRequest, userDisabled: true}

	attempts := []struct {
		name       string
		binding    string
		thumbprint string
		used       bool
		verifier   string
		want       *wantRefusal
		// reused is whether the answer is the reuse sentinel that drives the containment.
		reused     bool
		warnReason string
	}{
		{name: "a bound code with no proof", binding: boundKey, want: bindingRefusal, warnReason: "the request carries no dpop proof"},
		{name: "a bound code with a proof by another key", binding: boundKey, thumbprint: anotherKey, want: bindingRefusal,
			warnReason: "the request's dpop proof is by another key"},
		{name: "a bound code with a proof by its key", binding: boundKey, thumbprint: boundKey, want: disabledUser},
		{name: "an unbound code with no proof", want: disabledUser},
		{name: "an unbound code with a proof", thumbprint: anotherKey, want: disabledUser},
		{name: "a used bound code with no proof", binding: boundKey, used: true, want: bindingRefusal,
			warnReason: "the request carries no dpop proof"},
		{name: "a used bound code with a proof by another key", binding: boundKey, thumbprint: anotherKey, used: true,
			want: bindingRefusal, warnReason: "the request's dpop proof is by another key"},
		{name: "a used bound code with a proof by its key is reuse", binding: boundKey, thumbprint: boundKey, used: true,
			want: &wantRefusal{code: "invalid_grant", description: "Code is invalid.", status: http.StatusBadRequest}, reused: true},
		{
			// PKCE is answered first: the binding is the second proof the request owes, beside it.
			name: "a bound code with no proof and the wrong verifier", binding: boundKey, verifier: wrongCodeVerifier,
			want: &wantRefusal{code: "invalid_grant", description: "Invalid code_verifier (PKCE).", status: http.StatusBadRequest},
		},
	}

	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t),
				protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

			client := &record.Client{Id: 1, ClientIdentifier: "spa", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: true}
			code := &record.Code{
				Id:            42,
				RedirectURI:   redirectURI,
				ClientId:      client.Id,
				UserId:        7,
				CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
				CreatedAt:     sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Used:          a.used,
				DPoPJkt:       sql.NullString{String: a.binding, Valid: a.binding != ""},
			}
			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "spa").Return(client, nil).Once()
			if a.used {
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(code, nil).Once()
			} else {
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(code, nil).Once()
			}
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).
				Run(func(args mock.Arguments) { args.Get(2).(*record.Code).Client = *client }).Return(nil).Once()
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).
				Run(func(args mock.Arguments) { args.Get(2).(*record.Code).User = record.User{Id: 7, Enabled: false} }).Return(nil).Once()

			verifier := testCodeVerifier
			if a.verifier != "" {
				verifier = a.verifier
			}
			capture := logtest.CaptureSlog(t)
			grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, &ValidateTokenRequestInput{
				GrantType:      "authorization_code",
				ClientId:       "spa",
				Code:           "the_code",
				RedirectURI:    redirectURI,
				CodeVerifier:   verifier,
				DPoPThumbprint: a.thumbprint,
			})
			assert.Nil(t, grant)
			assertRefusal(t, err, *a.want)

			var reusedErr *AuthCodeReusedError
			assert.Equal(t, a.reused, errors.As(err, &reusedErr), "whether the answer drives the reuse containment")
			mockDB.AssertNotCalled(t, "MarkCodeAsUsed", mock.Anything, mock.Anything, mock.Anything)

			var records []logtest.CapturedRecord
			for _, r := range capture.Records() {
				if r.Message == "authorization code refused for its dpop binding" {
					records = append(records, r)
				}
			}
			if a.warnReason == "" {
				assert.Empty(t, records)
				return
			}
			require.Len(t, records, 1, "one Warn record of the refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, a.warnReason, records[0].Attrs["reason"])
			assert.Equal(t, "spa", records[0].Attrs["client_identifier"])
			assert.EqualValues(t, 42, records[0].Attrs["code_id"])
		})
	}
}
