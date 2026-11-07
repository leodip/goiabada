package apihandlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/account/export answers the caller's own data as the administrator's download answers
// it, byte for byte apart from when it was made: the same document, gzip for a caller that accepts
// it, the same file name, Vary and Content-Length, and five minutes to send it (#782 decision 3). It
// records exported_own_user_data, naming the caller as both the user and who asked, once the answer
// has been sent, and never for a refusal or a failure (decision 4). The client guard, the step-up
// guard and the rate limit are the route's middleware, held by their own tests and the integration
// tier.

// accountExportStore is the account export's port: the admin export's store, which answers the
// fixture user by id, and the caller's row by subject.
type accountExportStore struct {
	*userExportStore
	bySubject []string
}

func (d *accountExportStore) GetUserBySubject(_ context.Context, _ *sql.Tx, subject string) (*record.User, error) {
	d.bySubject = append(d.bySubject, subject)
	if d.failing == "GetUserBySubject" || d.failing == "*" {
		return nil, d.err
	}
	for _, user := range d.users {
		if user.Subject == subject {
			copied := *user
			return &copied, nil
		}
	}
	return nil, nil
}

// anaSubject is the fixture user's subject, the caller of every account export here.
const anaSubject = "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b"

// accountExportRequest is the caller's own export with a console token whose sub is subject, the
// settings the issuer is read from, and the Accept-Encoding given, if any.
func accountExportRequest(subject string, acceptEncoding ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
	for _, value := range acceptEncoding {
		r.Header.Add("Accept-Encoding", value)
	}
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{
		Issuer:                          "https://auth.example.com",
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
	}))
	return setTokenContextWithClaims(r, map[string]interface{}{
		"scope": "authserver:manage-account", "sub": subject, "client_id": "admin-console-client",
	})
}

func serveAccountExport(t *testing.T, database *accountExportStore, r *http.Request) (*deadlineRecorder, *exportAudit) {
	t.Helper()
	rr := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	auditLogger := &exportAudit{recorder: rr.ResponseRecorder}
	HandleAccountExportGet(database, auditLogger, "https://auth.example.com").ServeHTTP(rr, r)
	return rr, auditLogger
}

// accountExportFixture holds the fixture user and nothing else about them.
func accountExportFixture() *accountExportStore {
	return &accountExportStore{userExportStore: exportDatabase()}
}

func TestHandleAccountExportGet_AnswersTheCallersOwnDocumentAsAFileToSave(t *testing.T) {
	database := accountExportFixture()
	before := time.Now()

	rr, _ := serveAccountExport(t, database, accountExportRequest(anaSubject))

	after := time.Now()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{anaSubject}, database.bySubject, "the user is the token's subject")
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Empty(t, rr.Header().Get("Content-Encoding"), "a caller that names no encoding gets plain JSON")
	assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))
	assert.Equal(t, strconv.Itoa(rr.Body.Len()), rr.Header().Get("Content-Length"))

	exportedAt := assertTheFixtureDocument(t, rr.Body.Bytes(), before, after)
	assert.Equal(t, `attachment; filename="user-42-`+exportedAt.UTC().Format("2006-01-02")+`.json"`,
		rr.Header().Get("Content-Disposition"))
}

// The answer is the administrator's download of the same user, byte for byte, but for the instant
// each was made: the same document, headers and file name.
func TestHandleAccountExportGet_IsTheAdministratorsDownloadOfTheUser(t *testing.T) {
	for _, acceptEncoding := range []string{"", "gzip"} {
		t.Run("Accept-Encoding "+acceptEncoding, func(t *testing.T) {
			own, _ := serveAccountExport(t, accountExportFixture(), accountExportRequest(anaSubject, acceptEncoding))
			admin, _ := serveExport(t, exportDatabase(), exportRequest("42", acceptEncoding))

			require.Equal(t, http.StatusOK, own.Code)
			require.Equal(t, http.StatusOK, admin.Code)
			for _, name := range []string{"Content-Type", "Content-Encoding", "Vary"} {
				assert.Equal(t, admin.Header().Values(name), own.Header().Values(name), name)
			}
			// The length is each answer's own, since exportedAt's digits differ between the two.
			assert.Equal(t, strconv.Itoa(own.Body.Len()), own.Header().Get("Content-Length"))
			ownBody, adminBody := plainBody(t, own), plainBody(t, admin)
			assert.Equal(t, withoutExportedAt(t, adminBody), withoutExportedAt(t, ownBody))
		})
	}
}

// plainBody is the answer's body, gunzipped when it is gzip.
func plainBody(t *testing.T, rr *deadlineRecorder) []byte {
	t.Helper()
	if rr.Header().Get("Content-Encoding") != "gzip" {
		return rr.Body.Bytes()
	}
	reader, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	require.NoError(t, err, "the body is gzip")
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	return body
}

// withoutExportedAt is the body with its exportedAt value blanked, the one place two exports made at
// different instants differ.
func withoutExportedAt(t *testing.T, body []byte) string {
	t.Helper()
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &parts))
	require.Contains(t, parts, "exportedAt")
	at := string(parts["exportedAt"])
	return string(bytes.Replace(body, []byte(at), []byte(`""`), 1))
}

func TestHandleAccountExportGet_GzipWhenTheCallerAcceptsIt(t *testing.T) {
	before := time.Now()

	rr, _ := serveAccountExport(t, accountExportFixture(), accountExportRequest(anaSubject, "gzip, deflate, br"))

	after := time.Now()
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))
	assertTheFixtureDocument(t, plainBody(t, rr), before, after)
}

// The answer has five minutes to reach the caller, as the administrator's does.
func TestHandleAccountExportGet_LiftsTheWriteDeadlineToFiveMinutes(t *testing.T) {
	before := time.Now()

	rr, _ := serveAccountExport(t, accountExportFixture(), accountExportRequest(anaSubject))

	after := time.Now()
	require.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, rr.deadlines, 1)
	assert.False(t, rr.deadlines[0].Before(before.Add(5*time.Minute)) || rr.deadlines[0].After(after.Add(5*time.Minute)),
		"the deadline %v is not five minutes after the request", rr.deadlines[0])
}

// A download writes exported_own_user_data naming the caller as the user and as who asked, once the
// whole answer has been written.
func TestHandleAccountExportGet_RecordsTheDownloadAfterTheAnswer(t *testing.T) {
	for _, acceptEncoding := range []string{"", "gzip"} {
		t.Run("Accept-Encoding "+acceptEncoding, func(t *testing.T) {
			rr, auditLogger := serveAccountExport(t, accountExportFixture(), accountExportRequest(anaSubject, acceptEncoding))

			require.Equal(t, http.StatusOK, rr.Code)
			require.Len(t, auditLogger.events, 1)
			event := auditLogger.events[0]
			assert.Equal(t, "exported_own_user_data", event.event)
			assert.Equal(t, map[string]interface{}{
				"user_id":        int64(42),
				"logged_in_user": anaSubject,
			}, event.details)
			assert.Equal(t, rr.Body.Len(), event.bodyWritten, "the event is written once the whole answer is")
		})
	}
}

// An answer the caller did not receive whole is still recorded: part of the data has left the
// server either way.
func TestHandleAccountExportGet_RecordsADownloadTheCallerDidNotReceiveWhole(t *testing.T) {
	rr := httptest.NewRecorder()
	auditLogger := &exportAudit{recorder: rr}

	HandleAccountExportGet(accountExportFixture(), auditLogger, "https://auth.example.com").ServeHTTP(
		&interruptedWriter{rr}, accountExportRequest(anaSubject))

	require.Positive(t, rr.Body.Len(), "part of the document left the server")
	require.Len(t, auditLogger.events, 1)
	assert.Equal(t, "exported_own_user_data", auditLogger.events[0].event)
}

// A refused or failed download answers the API's error envelope, uncompressed whatever the caller
// accepts, and records nothing.
func TestHandleAccountExportGet_RefusalsAndFailuresAreUncompressedAndUnrecorded(t *testing.T) {
	for _, c := range []struct {
		name     string
		subject  string
		database *accountExportStore
		status   int
		code     string
	}{
		{"a subject that names no user", "00000000-0000-0000-0000-000000000000", accountExportFixture(),
			http.StatusNotFound, "NOT_FOUND"},
		{"a failed read of the user", anaSubject, &accountExportStore{userExportStore: &userExportStore{
			users: exportDatabase().users, failing: "GetUserBySubject", err: errs.New("the database is down")}},
			http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
		{"a failed read of a part", anaSubject, &accountExportStore{userExportStore: &userExportStore{
			users: exportDatabase().users, failing: "GetAuditLogsByUserId", err: errs.New("the database is down")}},
			http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
	} {
		t.Run(c.name, func(t *testing.T) {
			logtest.CaptureSlog(t)

			rr, auditLogger := serveAccountExport(t, c.database, accountExportRequest(c.subject, "gzip"))

			assert.Equal(t, c.status, rr.Code)
			assert.Empty(t, rr.Header().Get("Content-Encoding"))
			assert.Empty(t, rr.Header().Get("Content-Disposition"))
			var envelope map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope), "a plain JSON envelope: %q", rr.Body.String())
			assert.Equal(t, c.code, envelope["error_code"])
			assert.Empty(t, auditLogger.events)
		})
	}
}

// A request that reached the handler with no settings, or with no validated token, is a wiring
// fault: the API's 500, recorded nowhere.
func TestHandleAccountExportGet_WiringFaultsAreAFiveHundred(t *testing.T) {
	noSettings := setTokenContextWithClaims(httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil),
		map[string]interface{}{"scope": "authserver:manage-account", "sub": anaSubject})
	noToken := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
	noToken = noToken.WithContext(reqctx.WithSettings(noToken.Context(), &record.Settings{Issuer: "https://auth.example.com"}))

	for name, r := range map[string]*http.Request{"no settings": noSettings, "no token": noToken} {
		t.Run(name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)

			rr, auditLogger := serveAccountExport(t, accountExportFixture(), r)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Empty(t, auditLogger.events)
			assert.Len(t, capture.Records(), 1)
		})
	}
}
