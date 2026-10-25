package authflow

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/oauth"
)

// The five validations run in order and the first refusal ends them; a validator's fault is
// returned rather than taken for a refusal; and the prompt, once accepted, is kept when the hint
// after it is refused, so a parked ceremony carries it as it always did. The handler cases show
// each validation's refusal reaching the client (#437 seam 4).
func TestValidateAuthorizeRequest(t *testing.T) {
	requestRefusal := oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The request is invalid.", http.StatusBadRequest)

	testCases := []struct {
		name            string
		hint            string
		scope           string
		requestErr      error
		scopesErr       error
		wantRefusalCode string
		wantPrompt      string
		wantHint        string
		wantFault       bool
		wantCalls       []string
	}{
		{
			name:       "every validation accepts",
			wantPrompt: "login",
			wantCalls:  []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt"},
		},
		{
			name:            "the first refusal ends the validations",
			requestErr:      requestRefusal,
			wantRefusalCode: "invalid_request",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest"},
		},
		{
			name:      "a validator's fault is returned, not refused",
			scopesErr: errors.New("the database is unavailable"),
			wantFault: true,
			wantCalls: []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes"},
		},
		{
			// After the scopes, which establish that it exists, and before the prompt (#499).
			name:            "an administrative scope the client may not request is refused after the scopes",
			scope:           "openid authserver:manage",
			wantRefusalCode: "invalid_scope",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes"},
		},
		{
			name:            "a refused hint keeps the accepted prompt",
			hint:            "not-a-token",
			wantRefusalCode: "invalid_request",
			wantPrompt:      "login",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt", "DecodeAndValidateTokenString"},
		},
		{
			// The parser could not check the hint, so nothing is known of it: a fault (#680).
			name:      "a hint the parser could not check is a fault, not refused",
			hint:      "unchecked-hint",
			wantFault: true,
			wantCalls: []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt", "DecodeAndValidateTokenString"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			tokenParser := handlersmocks.NewTokenParser(t)
			var calls []string
			recordCall := func(name string) func(mock.Arguments) {
				return func(mock.Arguments) { calls = append(calls, name) }
			}

			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).
				Run(recordCall("ValidateUnsupportedRequestParameters")).Return(nil).Maybe()
			authorizeValidator.On("ValidateRequest", mock.Anything).
				Run(recordCall("ValidateRequest")).Return(tc.requestErr).Maybe()
			scope := "openid"
			if tc.scope != "" {
				scope = tc.scope
			}
			authorizeValidator.On("ValidateScopes", mock.Anything, scope).
				Run(recordCall("ValidateScopes")).Return(tc.scopesErr).Maybe()
			authorizeValidator.On("ValidatePrompt", "login").
				Run(recordCall("ValidatePrompt")).Return("login", nil).Maybe()
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "not-a-token", false).
				Run(recordCall("DecodeAndValidateTokenString")).
				Return(nil, fmt.Errorf("token is malformed: %w", signingkeys.ErrTokenRefused)).Maybe()
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "unchecked-hint", false).
				Run(recordCall("DecodeAndValidateTokenString")).
				Return(nil, errors.New("the signing keys could not be read")).Maybe()

			// ValidateScopes is handed the scope as sent, never the request's normalized copy, whose
			// spaces would hide a malformed one (#244): the copy below differs, so a call with it
			// matches no expectation.
			params := url.Values{"prompt": {"login"}, "scope": {scope}}
			if tc.hint != "" {
				params.Set("id_token_hint", tc.hint)
			}

			// The administrative check reads the request's normalized copy, which here is the scope
			// as sent, so a row asking for an administrative scope is judged on it.
			normalized := "the normalized copy"
			if tc.scope != "" {
				normalized = tc.scope
			}
			validation, err := validateAuthorizeRequest(context.Background(), authorizeValidator, tokenParser,
				&record.Settings{Issuer: "https://test-issuer.com"}, &record.Client{ClientIdentifier: "test-client"}, params,
				&protocolvalidation.ValidateRequestInput{Scope: normalized})

			assert.Equal(t, tc.wantCalls, calls)
			if tc.wantFault {
				require.Error(t, err)
				assert.Nil(t, validation.refusal)
				return
			}
			require.NoError(t, err)
			if tc.wantRefusalCode == "" {
				assert.Nil(t, validation.refusal)
			} else {
				require.NotNil(t, validation.refusal)
				assert.Equal(t, tc.wantRefusalCode, validation.refusal.Code())
			}
			if tc.scope != "" {
				assert.Equal(t, []string{"authserver:manage"}, validation.refusedAdministrativeScopes)
			} else {
				assert.Nil(t, validation.refusedAdministrativeScopes)
			}
			assert.Equal(t, tc.wantPrompt, validation.prompt)
			assert.Equal(t, tc.wantHint, validation.hintSubject)
		})
	}
}

// TestValidateIdTokenHint_TypeOfToken: a validly signed token of this server that is not an ID
// Token is refused as a hint, with the answer a hint that does not parse gets, so the reply does
// not say which kind of token was sent (#401). ID Tokens carry no typ at all, so the absent row is
// the one a real hint takes.
func TestValidateIdTokenHint_TypeOfToken(t *testing.T) {
	settings := &record.Settings{Issuer: "https://test-issuer.com"}

	tests := []struct {
		name     string
		typ      interface{} // nil leaves the claim out
		accepted bool
	}{
		{name: "ID Token, no typ", typ: nil, accepted: true},
		{name: "access token", typ: "Bearer"},
		{name: "session refresh token", typ: "Refresh"},
		{name: "offline refresh token", typ: "Offline"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "https://test-issuer.com", "sub": "user-123"}
			if tc.typ != nil {
				claims["typ"] = tc.typ
			}
			tokenParser := handlersmocks.NewTokenParser(t)
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-hint", false).
				Return(&oauth.JwtToken{TokenBase64: "the-hint", Claims: claims}, nil)

			sub, err := validateIdTokenHint(context.Background(), "the-hint", tokenParser, settings)

			if tc.accepted {
				require.NoError(t, err)
				assert.Equal(t, "user-123", sub)
				return
			}
			assert.Empty(t, sub)
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Equal(t, "The id_token_hint is invalid.", detail.Description())
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
		})
	}
}

// TestValidateIdTokenHint_TheParsersAnswer: a hint the parser refuses, expired included, is the
// invalid_request every bad hint gets, and a hint it could not check, because the signing keys could
// not be read, is returned as the fault itself, which the handler answers on its server error page,
// rather than telling the client a hint that may be good is invalid (#680).
func TestValidateIdTokenHint_TheParsersAnswer(t *testing.T) {
	settings := &record.Settings{Issuer: "https://test-issuer.com"}
	keyStoreDown := errors.New("the signing keys could not be read")

	tests := []struct {
		name      string
		parserErr error
		wantFault bool
	}{
		{name: "refused", parserErr: fmt.Errorf("token signature is invalid: %w", signingkeys.ErrTokenRefused)},
		{name: "refused as expired",
			parserErr: fmt.Errorf("token is expired: %w", errors.Join(signingkeys.ErrTokenRefused, signingkeys.ErrTokenExpired))},
		{name: "could not be checked", parserErr: keyStoreDown, wantFault: true},
		{name: "could not be checked, joined to the library's error",
			parserErr: errors.Join(jwt.ErrTokenSignatureInvalid, keyStoreDown), wantFault: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenParser := handlersmocks.NewTokenParser(t)
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-hint", false).Return(nil, tc.parserErr)

			sub, err := validateIdTokenHint(context.Background(), "the-hint", tokenParser, settings)

			assert.Empty(t, sub)
			var detail *oauth.ErrorDetail
			if tc.wantFault {
				require.ErrorIs(t, err, keyStoreDown)
				assert.NotErrorAs(t, err, &detail, "a fault is not a refusal of the hint")
				return
			}
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Equal(t, "The id_token_hint is invalid.", detail.Description())
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
		})
	}
}

// formReads answers every string literal the file reads a parameter by: a Get call on a receiver
// isReceiver accepts, or an index into one.
func formReads(t *testing.T, file string, isReceiver func(ast.Expr) bool) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)

	var reads []string
	literal := func(e ast.Expr) {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			value, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			reads = append(reads, value)
		}
	}
	ast.Inspect(parsed, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Get" && isReceiver(sel.X) && len(n.Args) == 1 {
				literal(n.Args[0])
			}
		case *ast.IndexExpr:
			if isReceiver(n.X) {
				literal(n.Index)
			}
		}
		return true
	})
	require.NotEmpty(t, reads, "the walk found no parameter read in %v, so it proves nothing", file)
	return reads
}

// A parameter read that is not listed is a parameter whose repeats are never checked, which is the
// defect #228 closes coming back one read at a time.
func TestAuthorizeRequestParameters_EveryReadIsListed(t *testing.T) {
	reads := formReads(t, "authorization.go", func(e ast.Expr) bool {
		ident, ok := e.(*ast.Ident)
		return ok && ident.Name == "params"
	})
	for _, name := range reads {
		assert.Contains(t, authorizeRequestParameters, name, "authorization.go reads %q", name)
	}
	for _, name := range authorizeDeliveryParameters {
		assert.Contains(t, authorizeRequestParameters, name)
	}
	for _, name := range authorizeRequestParameters {
		assert.True(t, slices.Contains(reads, name), "%q is listed but nothing reads it", name)
	}
}
