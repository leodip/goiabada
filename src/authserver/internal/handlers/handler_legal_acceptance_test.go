package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/mock"
)

// legalAcceptanceTx is the transaction an accepted step records its acceptances in.
var legalAcceptanceTx = &sql.Tx{}

// The acceptance step answers a fault with the 500 page and moves the ceremony nowhere: nothing
// saved, cleared or audited. A step that moved on after a failed read of what is owed, or after an
// acceptance that was never recorded, would let a user past a document they owe (#622).
func TestHandleLegalAcceptance_AFailureAnswers500AndMovesNothingOn(t *testing.T) {
	failure := errors.New("read failed")
	owedTerms := []legaldocuments.InEffect{{
		Document: record.LegalDocument{Id: 3, ShortName: "terms", Kind: record.LegalDocumentKindMustAccept},
		Current:  record.LegalDocumentVersion{Id: 31, LegalDocumentId: 3, VersionNumber: 1},
	}}
	accept := url.Values{"btnAccept": {"accept"}, "shownVersion": {"31"}, "legalDocument": {"31"}}

	for _, tc := range []struct {
		name      string
		method    string
		owed      *owedRead
		recording func(database *datamocks.Database)
	}{
		{name: "the page, with what is owed unreadable", method: http.MethodGet, owed: &owedRead{err: failure}},
		{name: "an acceptance, with what is owed unreadable", method: http.MethodPost, owed: &owedRead{err: failure}},
		{name: "an acceptance the database refuses to record", method: http.MethodPost, owed: &owedRead{owed: owedTerms},
			recording: func(database *datamocks.Database) {
				datamocks.ExpectRunInTransaction(database, legalAcceptanceTx)
				database.On("GetLegalDocumentAcceptancesByUserId", mock.Anything, legalAcceptanceTx, int64(1)).
					Return([]record.LegalDocumentAcceptance{}, nil).Once()
				database.On("CreateLegalDocumentAcceptance", mock.Anything, legalAcceptanceTx, mock.Anything).
					Return(failure).Once()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			deps := legalAcceptanceDeps{
				pageRenderer:      pageRenderer,
				ceremonyStore:     ceremonyStore,
				database:          database,
				templateFS:        fstest.MapFS{},
				auditLogger:       auditLogger,
				permissionChecker: handlersmocks.NewPermissionChecker(t),
				legalDocuments:    tc.owed,
			}

			var req *http.Request
			var handler http.HandlerFunc
			if tc.method == http.MethodGet {
				req = httptest.NewRequest(http.MethodGet, "/auth/legal-acceptance?ceremony="+testCeremonyId, nil)
				handler = buildLegalAcceptanceGet(deps)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/auth/legal-acceptance", strings.NewReader(accept.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				handler = buildLegalAcceptancePost(deps)
			}
			req = withSessionSettings(req)
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", req).Return(&ceremony.AuthContext{
				CeremonyId: testCeremonyId,
				AuthState:  ceremony.AuthStateRequiresLegalAcceptance,
				ClientId:   "test-client",
				UserId:     1,
				Scope:      "openid",
			}, nil).Once()
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
				Return(&record.Client{Id: 7, ClientIdentifier: "test-client"}, nil).Once()
			database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
				Return(&record.User{Id: 1, Enabled: true}, nil).Once()
			if tc.recording != nil {
				tc.recording(database)
			}
			pageRenderer.On("InternalServerError", rr, req, failure).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAcceptedLegalDocument, mock.Anything)
		})
	}
}
