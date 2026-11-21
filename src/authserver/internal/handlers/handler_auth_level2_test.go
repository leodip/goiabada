package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

func TestHandleAuthLevel2Get(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		expectedError := &oauth.ErrorDetail{}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedError)
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateReadyToIssueCode,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		expectAuthStateMismatch(t, pageRenderer, rr, req)

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Client not found", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client test-client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACRLevel2Optional with OTP enabled", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
			UserID:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &record.Client{
			ID:               1,
			ClientIdentifier: "test-client",
			DefaultACRLevel:  record.ACRLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &record.User{
			ID:                  1,
			OTPEnabled:          true,
			OTPConfigGeneration: 4,
		}
		database.On("GetUserByID", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateLevel2OTP &&
				ac.OTPConfigGeneration != nil && *ac.OTPConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/otp?ceremony="+testCeremonyID, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACRLevel2Optional with OTP disabled", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
			UserID:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &record.Client{
			ID:               1,
			ClientIdentifier: "test-client",
			DefaultACRLevel:  record.ACRLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &record.User{
			ID:                  1,
			OTPEnabled:          false,
			OTPConfigGeneration: 4,
		}
		database.On("GetUserByID", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		// **The skip arm captures too**, and that is the case worth pinning: a user who has
		// removed their authenticator answers the level 2 question by having nothing to
		// answer with, so this ceremony must discharge the obligation. Without the capture
		// here every session of such a user stays permanently behind and prompt=none
		// answers interaction_required for the rest of each session's life (#242 decision 3).
		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateAuthenticationCompleted &&
				ac.OTPConfigGeneration != nil && *ac.OTPConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/completed?ceremony="+testCeremonyID, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACRLevel2Mandatory", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
			UserID:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &record.Client{
			ID:               1,
			ClientIdentifier: "test-client",
			DefaultACRLevel:  record.ACRLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &record.User{
			ID:                  1,
			OTPConfigGeneration: 4,
		}
		database.On("GetUserByID", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateLevel2OTP &&
				ac.OTPConfigGeneration != nil && *ac.OTPConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/otp?ceremony="+testCeremonyID, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// Part 4. GetUserByID answers (nil, nil) for a row that is not there, so a user deleted
	// mid-ceremony used to reach `if user.OTPEnabled` and panic with a nil pointer
	// dereference, logged at status 0 (#203) because the panic escapes before the status is
	// written. Every sibling ceremony handler already checks this; this one did not, and
	// "every handler except one" is the kind of gap that regresses (#242 decision 5).
	t.Run("User not found", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
			UserID:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &record.Client{
			ID:               1,
			ClientIdentifier: "test-client",
			DefaultACRLevel:  record.ACRLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		database.On("GetUserByID", mock.Anything, mock.Anything, int64(1)).Return(nil, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		// Nothing is saved and nothing is redirected: the ceremony stops here. NewCeremonyStore(t)
		// fails on an unregistered SaveAuthContext, and this says so in its own words.
		ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		assert.Empty(t, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Invalid ACRLevel", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)

		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := buildAuthLevel2Get(authLevel2GetDeps{
			pageRenderer:  pageRenderer,
			ceremonyStore: ceremonyStore,
			database:      database,
			auditLogger:   auditLogger,
		})

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyID, nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyID: testCeremonyID,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientID:   "test-client",
			UserID:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &record.Client{
			ID:               1,
			ClientIdentifier: "test-client",
			DefaultACRLevel:  record.ACRLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &record.User{
			ID: 1,
		}
		database.On("GetUserByID", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid targetAcrLevel: urn:goiabada:level1"
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

// A failed read of the client or of the user answers 500 carrying the read's own error, and the
// ceremony is not saved: the user is not read after a failed client read, and nothing is redirected.
func TestHandleAuthLevel2Get_AFailedReadAnswers500AndSavesNothing(t *testing.T) {
	readFailure := errors.New("read failed")

	for _, tc := range []struct {
		name string
		arm  func(database *datamocks.Database)
	}{
		{"the client", func(database *datamocks.Database) {
			database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "test-client").Return(nil, readFailure).Once()
		}},
		{"the user", func(database *datamocks.Database) {
			database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "test-client").Return(
				&record.Client{ID: 1, ClientIdentifier: "test-client", DefaultACRLevel: record.ACRLevel2Optional}, nil).Once()
			database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(nil, readFailure).Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			handler := buildAuthLevel2Get(authLevel2GetDeps{
				pageRenderer:  pageRenderer,
				ceremonyStore: ceremonyStore,
				database:      database,
				auditLogger:   handlersmocks.NewAuditLogger(t),
			})

			req := withSessionSettings(httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyID, nil))
			rr := httptest.NewRecorder()
			authContext := &ceremony.AuthContext{
				CeremonyID: testCeremonyID,
				AuthState:  ceremony.AuthStateRequiresLevel2,
				ClientID:   "test-client",
				UserID:     1,
			}
			ceremonyStore.On("GetAuthContext", req).Return(authContext, nil)
			tc.arm(database)
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
				return errors.Is(err, readFailure)
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			database.AssertExpectations(t)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			assert.Nil(t, authContext.OTPConfigGeneration, "no generation is captured from a user never read")
			assert.Empty(t, rr.Header().Get("Location"))
		})
	}
}
