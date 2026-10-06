package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// A refusal of administrative scopes at the token endpoint is recorded as
// administrative_scope_refused once the client has authenticated, which the validator returns it
// only after: the client, the scopes refused, the grant as the checkpoint, and the user they were
// asked for (#499 decision 9). The client is answered with the validator's own detail. Wrapped
// once, as a validator's result may be, so the match is shown to go through the chain.
func TestHandleTokenPost_AdministrativeScopeRefusalIsAudited(t *testing.T) {
	client := &record.Client{Id: 3, ClientIdentifier: "app"}

	for _, tc := range []struct {
		name        string
		form        string
		detail      *oauth.ErrorDetail
		checkpoint  string
		scopeDenied bool
	}{
		{
			name: "refresh token grant",
			form: "grant_type=refresh_token&client_id=app&client_secret=s&refresh_token=rt",
			detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"Scope 'authserver:manage' is not recognized. The client is not allowed to request the administrative scope 'authserver:manage'.",
				http.StatusBadRequest),
			checkpoint: "refresh_token",
		},
		{
			// invalid_scope, so the token_scope_denied row every authenticated invalid_scope writes
			// is written beside it.
			name: "password grant",
			form: "grant_type=password&client_id=app&username=u%40example.com&password=p&scope=openid+authserver%3Amanage",
			detail: oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				"The client is not allowed to request the administrative scope 'authserver:manage'.",
				http.StatusBadRequest),
			checkpoint:  "password",
			scopeDenied: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter := handlersmocks.NewJSONWriter(t)
			tokenValidator := handlersmocks.NewTokenValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := HandleTokenPost(jsonWriter, datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t), tokenValidator,
				auditLogger, noCredentialFailures{}, testTokenMetrics())

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(tc.form))
			req = withSettings(req, &record.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			refusal := &protocolvalidation.AdministrativeScopeRefusedError{
				Detail: tc.detail,
				Client: client,
				Scopes: []string{"authserver:manage"},
				UserId: 7,
			}
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
				mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
				Return(nil, errs.Wrap(refusal, "unable to validate the token request"))

			auditLogger.On("Log", mock.Anything, audit.EventAdministrativeScopeRefused, map[string]interface{}{
				"clientId":         int64(3),
				"clientIdentifier": "app",
				"scopes":           []string{"authserver:manage"},
				"checkpoint":       tc.checkpoint,
				"userId":           int64(7),
			}).Return().Once()
			if tc.scopeDenied {
				auditLogger.On("Log", mock.Anything, audit.EventTokenScopeDenied, mock.Anything).Return().Once()
			}
			captured := expectJSONErrorWithDetail(jsonWriter)

			handler.ServeHTTP(rr, req)

			var detail *oauth.ErrorDetail
			require.ErrorAs(t, *captured, &detail)
			assert.Same(t, tc.detail, detail)
		})
	}
}
