package ceremony

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestFields are the AuthContext fields that describe the authorization request: written at
// /auth/authorize, when the request is accepted, and kept by Restart. attemptFields are everything
// an authentication writes, and Restart discards them. Every field is in exactly one list, which
// TestAuthContextFields_EveryFieldIsClassifiedOnce holds against the struct, so a field added to
// AuthContext fails the unit tier until somebody decides which of the two it is (#436).
var requestFields = []string{
	"CeremonyId",
	"ClientId",
	"RedirectURI",
	"ResponseType",
	"CodeChallengeMethod",
	"CodeChallenge",
	"ResponseMode",
	"MaxAge",
	"AcrValuesFromAuthorizeRequest",
	"State",
	"Nonce",
	"UserAgent",
	"IpAddress",
	"UILocales",
	"Prompt",
	"IdTokenHintSub",
	"TargetAcrLevel",
	"DeferredErrorCode",
	"DeferredErrorDescription",
	"RequestedScope",
}

var attemptFields = []string{
	"AuthState",
	"Scope",
	"ConsentedScope",
	"UserId",
	"AcrLevel",
	"AuthMethods",
	"AuthenticatedAt",
	"Level1AuthCompleted",
	"AuthStateGeneration",
	"OtpConfigGeneration",
	"OTPKeyURL",
	"PasswordVerifiedAt",
	"OtpClaimGeneration",
}

// restartedTo names the two attempt fields a restart does not leave at their zero value: the
// state it restarts into, and the working scope it puts back from the request. Every other attempt
// field is zero after Restart.
func restartedTo(filled *AuthContext) map[string]any {
	return map[string]any{
		"AuthState": AuthStateRequiresLevel1,
		"Scope":     filled.RequestedScope,
	}
}

func TestAuthContextFields_EveryFieldIsClassifiedOnce(t *testing.T) {
	contextType := reflect.TypeOf(AuthContext{})
	declared := make([]string, 0, contextType.NumField())
	for i := range contextType.NumField() {
		declared = append(declared, contextType.Field(i).Name)
	}

	for _, name := range declared {
		inRequest := slices.Contains(requestFields, name)
		inAttempt := slices.Contains(attemptFields, name)
		assert.NotEqualf(t, inRequest, inAttempt,
			"AuthContext.%s must be in exactly one of requestFields and attemptFields (request: %v, attempt: %v)",
			name, inRequest, inAttempt)
	}
	for _, name := range slices.Concat(requestFields, attemptFields) {
		assert.Containsf(t, declared, name, "%s is classified but AuthContext declares no such field", name)
	}
	assert.Len(t, slices.Concat(requestFields, attemptFields), len(declared),
		"a field listed twice in one list is still one field")
}

// fillEveryField gives every field of the context a non-zero value derived from its name and
// position, the same on every call, so two calls produce equal contexts sharing no memory. A kind
// it does not know fails the test rather than being skipped, so a new field of a new kind is filled
// before it can be classified.
func fillEveryField(t *testing.T, ac *AuthContext) {
	t.Helper()
	value := reflect.ValueOf(ac).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		name := value.Type().Field(i).Name
		switch {
		case field.Kind() == reflect.String:
			field.SetString(name + "-value")
		case field.Kind() == reflect.Int64:
			field.SetInt(int64(i + 1))
		case field.Kind() == reflect.Bool:
			field.SetBool(true)
		case field.Type() == reflect.TypeOf(&time.Time{}):
			instant := time.Date(2026, 9, 29, 12, 0, i, 0, time.UTC)
			field.Set(reflect.ValueOf(&instant))
		case field.Type() == reflect.TypeOf(new(int64)):
			number := int64(100 + i)
			field.Set(reflect.ValueOf(&number))
		case field.Type() == reflect.TypeOf([]string{}):
			field.Set(reflect.ValueOf([]string{name + "-a", name + "-b"}))
		default:
			t.Fatalf("fillEveryField does not know how to fill AuthContext.%s of type %s", name, field.Type())
		}
		require.Falsef(t, field.IsZero(), "AuthContext.%s was left at its zero value", name)
	}
}

func TestRestart_KeepsTheRequestAndDiscardsTheAttempt(t *testing.T) {
	var restarted, filled AuthContext
	fillEveryField(t, &restarted)
	fillEveryField(t, &filled)
	require.NotEqual(t, filled.Scope, filled.RequestedScope,
		"the working scope must differ from the requested one, or restoring it proves nothing")

	restarted.Restart()

	after := reflect.ValueOf(restarted)
	before := reflect.ValueOf(filled)
	for _, name := range requestFields {
		assert.Equalf(t, before.FieldByName(name).Interface(), after.FieldByName(name).Interface(),
			"request field %s must survive a restart", name)
	}
	nonZero := restartedTo(&filled)
	for _, name := range attemptFields {
		if want, ok := nonZero[name]; ok {
			assert.Equalf(t, want, after.FieldByName(name).Interface(), "attempt field %s after a restart", name)
			continue
		}
		assert.Truef(t, after.FieldByName(name).IsZero(),
			"attempt field %s must be discarded by a restart, got %v", name, after.FieldByName(name).Interface())
	}
}

// TestRestart_ALegacyContextRestartsWithAnEmptyScope restarts a context written before
// RequestedScope existed. It decodes as "", so the scope restored from it is empty too, and
// /auth/completed answers that access_denied. Falling back to the narrowed Scope instead would
// hand the first user's narrowing to whoever completes the second pass, which is what RequestedScope
// was added to stop, so the empty scope is the intended outcome and not an accident (#436).
func TestRestart_ALegacyContextRestartsWithAnEmptyScope(t *testing.T) {
	var ac AuthContext
	require.NoError(t, json.Unmarshal([]byte(populatedAuthContextJSON), &ac))
	require.Equal(t, "openid profile", ac.Scope)
	require.Equal(t, "openid", ac.ConsentedScope)
	require.Empty(t, ac.RequestedScope)

	ac.Restart()

	assert.Equal(t, AuthContext{
		ClientId:                      "client-one",
		RedirectURI:                   "https://rp.example/cb",
		ResponseType:                  "code",
		CodeChallengeMethod:           "S256",
		CodeChallenge:                 "challenge",
		ResponseMode:                  "query",
		MaxAge:                        "300",
		AcrValuesFromAuthorizeRequest: "urn:goiabada:level2_optional",
		State:                         "state-value",
		Nonce:                         "nonce-value",
		UserAgent:                     "probe/1.0",
		IpAddress:                     "203.0.113.7",
		AuthState:                     AuthStateRequiresLevel1,
		Prompt:                        "consent",
		IdTokenHintSub:                "sub-value",
		CeremonyId:                    "ceremony-1",
		UILocales:                     []string{"pt-BR", "en"},
		DeferredErrorCode:             "invalid_scope",
		DeferredErrorDescription:      "bad scope",
		TargetAcrLevel:                "urn:goiabada:level2_mandatory",
	}, ac)
}
