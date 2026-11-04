package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The password page asks Keep me signed in, with an unticked box, under Let each user choose alone,
// and the answer travels with the password on the ceremony to /auth/completed; under Always and
// Never there is no box and the password carries no answer (#743 decisions 2 and 4).

// boxField is the box's form field, and boxTicked the value a ticked box posts, as the template
// writes them.
const (
	boxField  = "keepSignedIn"
	boxTicked = "true"
)

func passwordPageCeremony() *ceremony.AuthContext {
	return &ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1Password, CeremonyId: testCeremonyId,
		ClientId: "my-app"}
}

// The form shows the box under Let each user choose alone, and unticked.
func TestHandleAuthPwdGet_AsksKeepMeSignedInUnderLetEachUserChooseAlone(t *testing.T) {
	for _, tc := range []struct {
		mode      record.KeepSignedIn
		wantAsked bool
	}{
		{record.KeepSignedInAsk, true},
		{record.KeepSignedInAlways, false},
		{record.KeepSignedInNever, false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			handler := buildAuthPwdGet(authPwdGetDeps{pageRenderer: pageRenderer, ceremonyStore: ceremonyStore,
				database: database, auditLogger: handlersmocks.NewAuditLogger(t)})

			req := httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony="+testCeremonyId, nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{KeepSignedIn: tc.mode}))
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(passwordPageCeremony(), nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "my-app").
				Return(&record.Client{ClientIdentifier: "my-app"}, nil)
			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html",
				mock.MatchedBy(func(data map[string]interface{}) bool { rendered = data; return true })).Return(nil)

			handler.ServeHTTP(rr, req)

			require.NotNil(t, rendered)
			assert.Equal(t, tc.wantAsked, rendered["keepSignedInAsked"])
			assert.Equal(t, false, rendered["keepSignedIn"], "the box starts unticked: a pre-ticked box is not consent")
		})
	}
}

// A refused submission draws the form again with the box as the user left it.
func TestHandleAuthPwdPost_ARefusalRedrawsTheBoxAsLeft(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        record.KeepSignedIn
		posted      string
		wantAsked   bool
		wantTicked  bool
		description string
	}{
		{"ticked", record.KeepSignedInAsk, boxTicked, true, true, "a ticked box stays ticked"},
		{"unticked", record.KeepSignedInAsk, "", true, false, "an unticked box stays unticked"},
		{"no box", record.KeepSignedInAlways, boxTicked, false, false, "a box the page does not show is not drawn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			handler := buildAuthPwdPost(authPwdPostDeps{pageRenderer: pageRenderer, ceremonyStore: ceremonyStore,
				database: database, auditLogger: handlersmocks.NewAuditLogger(t)})

			form := url.Values{ceremony.IdField: {testCeremonyId}, "email": {"alice@example.com"}}
			if tc.posted != "" {
				form.Set(boxField, tc.posted)
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{KeepSignedIn: tc.mode}))
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(passwordPageCeremony(), nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "my-app").
				Return(&record.Client{ClientIdentifier: "my-app"}, nil)
			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html",
				mock.MatchedBy(func(data map[string]interface{}) bool { rendered = data; return true })).Return(nil)

			handler.ServeHTTP(rr, req)

			require.NotNil(t, rendered)
			assert.Equal(t, "Password is required.", rendered["error"], "the refusal this case drives")
			assert.Equal(t, tc.wantAsked, rendered["keepSignedInAsked"])
			assert.Equal(t, tc.wantTicked, rendered["keepSignedIn"], tc.description)
		})
	}
}

// An accepted password saves the answer on the ceremony: ticked or unticked under Let each user
// choose, and none under Always or Never, whatever the request posts.
func TestHandleAuthPwdPost_SavesTheAnswerWithThePassword(t *testing.T) {
	ticked, unticked := true, false
	for _, tc := range []struct {
		name   string
		mode   record.KeepSignedIn
		posted string
		want   *bool
	}{
		{"Let each user choose, ticked", record.KeepSignedInAsk, boxTicked, &ticked},
		{"Let each user choose, unticked", record.KeepSignedInAsk, "", &unticked},
		{"Let each user choose, any other value", record.KeepSignedInAsk, "on-purpose", &unticked},
		{"Always, a box posted anyway", record.KeepSignedInAlways, boxTicked, nil},
		{"Always", record.KeepSignedInAlways, "", nil},
		{"Never, a box posted anyway", record.KeepSignedInNever, boxTicked, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := buildAuthPwdPost(authPwdPostDeps{pageRenderer: handlersmocks.NewPageRenderer(t),
				ceremonyStore: ceremonyStore, database: database, auditLogger: auditLogger})

			passwordHash, err := passwordhash.Hash("the-right-password")
			require.NoError(t, err)
			form := url.Values{ceremony.IdField: {testCeremonyId}, "email": {"alice@example.com"},
				"password": {"the-right-password"}}
			if tc.posted != "" {
				form.Set(boxField, tc.posted)
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{KeepSignedIn: tc.mode}))
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(passwordPageCeremony(), nil)
			database.On("GetUserByEmail", mock.Anything, mock.Anything, "alice@example.com").
				Return(&record.User{Id: 1, Email: "alice@example.com", PasswordHash: passwordHash, Enabled: true}, nil)
			auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessPwd, mock.Anything).Return()
			ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId, int64(1)).Return(nil).Once()
			var saved *ceremony.AuthContext
			ceremonyStore.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				saved = ac
				return true
			})).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusSeeOther, rr.Code)
			require.NotNil(t, saved)
			assert.Equal(t, tc.want, saved.KeepSignedIn)
		})
	}
}

// The box is read from the body alone, as every field of the form is: a query parameter answers
// nothing, so a link cannot tick it.
func TestHandleAuthPwdPost_ReadsTheBoxFromTheBodyAlone(t *testing.T) {
	unticked := false
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := buildAuthPwdPost(authPwdPostDeps{pageRenderer: handlersmocks.NewPageRenderer(t),
		ceremonyStore: ceremonyStore, database: database, auditLogger: auditLogger})

	passwordHash, err := passwordhash.Hash("the-right-password")
	require.NoError(t, err)
	form := url.Values{ceremony.IdField: {testCeremonyId}, "email": {"alice@example.com"},
		"password": {"the-right-password"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/pwd?"+boxField+"="+boxTicked,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{KeepSignedIn: record.KeepSignedInAsk}))
	rr := httptest.NewRecorder()

	ceremonyStore.On("GetAuthContext", mock.Anything).Return(passwordPageCeremony(), nil)
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "alice@example.com").
		Return(&record.User{Id: 1, Email: "alice@example.com", PasswordHash: passwordHash, Enabled: true}, nil)
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessPwd, mock.Anything).Return()
	ceremonyStore.On("RegenerateSession", rr, mock.Anything, testCeremonyId, int64(1)).Return(nil).Once()
	ceremonyStore.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return assert.Equal(t, &unticked, ac.KeepSignedIn)
	})).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}
