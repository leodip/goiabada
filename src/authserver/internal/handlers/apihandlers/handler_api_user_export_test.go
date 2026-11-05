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
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/users/{id}/export answers everything held about one user as one JSON document,
// named for download, gzip-compressed for a caller that accepts it, with five minutes to send it,
// and records exported_user_data once the answer is written (#781 decisions 3, 5, 6 and 8). The
// scope rule, decision 1, is the route's middleware, held by the integration tier.

// userExportUsers is the endpoint's port, implemented directly: the users it holds by id, or the
// failure every read answers.
type userExportUsers struct {
	users map[int64]*record.User
	err   error
	reads []int64
}

func (d *userExportUsers) GetUserById(_ context.Context, _ *sql.Tx, userId int64) (*record.User, error) {
	d.reads = append(d.reads, userId)
	if d.err != nil {
		return nil, d.err
	}
	return d.users[userId], nil
}

// exportAudit records each event the handler logs, with what the response held at that moment.
type exportAudit struct {
	recorder *httptest.ResponseRecorder
	events   []exportAuditEvent
}

type exportAuditEvent struct {
	event   string
	details map[string]interface{}
	// bodyWritten is how many bytes of the answer were written when the event was logged.
	bodyWritten int
}

func (a *exportAudit) Log(_ context.Context, auditEvent string, details map[string]interface{}) {
	a.events = append(a.events, exportAuditEvent{event: auditEvent, details: details, bodyWritten: a.recorder.Body.Len()})
}

// deadlineRecorder is a response recorder that, like a real connection, takes a write deadline.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.deadlines = append(d.deadlines, deadline)
	return nil
}

func exportFixtureUser() *record.User {
	return &record.User{
		Id:            42,
		CreatedAt:     sql.NullTime{Time: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), Valid: true},
		Enabled:       true,
		Subject:       "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b",
		GivenName:     "Ana",
		FamilyName:    "Silva",
		Email:         "ana.silva@example.com",
		EmailVerified: true,
		PasswordHash:  "$2a$10$theseededpasswordhashofana",
		// The OTP seed, encrypted at rest: never part of the document.
		OTPSecretEncrypted: []byte("the-seeded-otp-secret"),
		OTPEnabled:         true,
	}
}

// exportFixtureDocument is the document for exportFixtureUser, exportedAt aside, written out by
// hand from decision 3. The digest is `printf '%s' ana.silva@example.com | sha256sum`.
const exportFixtureDocument = `{
	"formatVersion": 1,
	"issuer": "https://auth.example.com",
	"identifiers": {
		"id": 42,
		"subject": "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b",
		"email": "ana.silva@example.com",
		"emailDigest": "7bda2560ce1bf126ff5df73ed84b6c9f8dd6064e33fc273eb05b7761e31c2b86"
	},
	"user": {
		"id": 42, "createdAt": "2025-01-02T03:04:05Z", "updatedAt": null, "enabled": true,
		"subject": "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b", "username": "", "givenName": "Ana",
		"middleName": "", "familyName": "Silva", "nickname": "", "website": "", "gender": "",
		"email": "ana.silva@example.com", "emailVerified": true, "zoneInfoCountryName": "",
		"zoneInfo": "", "locale": "", "pageLanguage": "", "birthDate": null,
		"phoneNumberCountryUniqueId": "", "phoneNumberCountryCallingCode": "", "phoneNumber": "",
		"phoneNumberVerified": false, "addressLine1": "", "addressLine2": "", "addressLocality": "",
		"addressRegion": "", "addressPostalCode": "", "addressCountry": "", "otpEnabled": true,
		"otpAuthenticatorDisabled": false
	},
	"attributes": [],
	"groups": [],
	"permissions": [],
	"consents": [],
	"sessions": [],
	"refreshTokens": [],
	"legalDocumentAcceptances": [],
	"profilePicture": null,
	"auditEvents": []
}`

// exportRequest is the export of the user id with a manage token whose sub is the caller an audit
// row names, the settings the issuer is read from, and the Accept-Encoding given, if any.
func exportRequest(id string, acceptEncoding ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+id+"/export", nil)
	for _, value := range acceptEncoding {
		r.Header.Add("Accept-Encoding", value)
	}
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{Issuer: "https://auth.example.com"}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": "the-administrator"})
	return withPathValue(r, "id", id)
}

func serveExport(t *testing.T, database *userExportUsers, r *http.Request) (*deadlineRecorder, *exportAudit) {
	t.Helper()
	rr := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	auditLogger := &exportAudit{recorder: rr.ResponseRecorder}
	HandleUserExportGet(database, auditLogger).ServeHTTP(rr, r)
	return rr, auditLogger
}

func exportDatabase() *userExportUsers {
	return &userExportUsers{users: map[int64]*record.User{42: exportFixtureUser()}}
}

// assertTheFixtureDocument holds a plain JSON body to the fixture's document, and exportedAt to an
// instant inside the request, in UTC. It answers that instant.
func assertTheFixtureDocument(t *testing.T, body []byte, before, after time.Time) time.Time {
	t.Helper()
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &parts), "%q", body)

	var exportedAt time.Time
	require.NoError(t, json.Unmarshal(parts["exportedAt"], &exportedAt))
	assert.True(t, strings.HasSuffix(string(parts["exportedAt"]), `Z"`), "exportedAt in UTC: %s", parts["exportedAt"])
	assert.False(t, exportedAt.Before(before.Truncate(time.Second)) || exportedAt.After(after), "exportedAt %v is not within the request", exportedAt)

	delete(parts, "exportedAt")
	rest, err := json.Marshal(parts)
	require.NoError(t, err)
	assert.JSONEq(t, exportFixtureDocument, string(rest))
	return exportedAt
}

func TestHandleUserExportGet_AnswersTheDocumentAsAFileToSave(t *testing.T) {
	database := exportDatabase()
	before := time.Now()

	rr, _ := serveExport(t, database, exportRequest("42"))

	after := time.Now()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []int64{42}, database.reads)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Empty(t, rr.Header().Get("Content-Encoding"), "a caller that names no encoding gets plain JSON")
	assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))

	exportedAt := assertTheFixtureDocument(t, rr.Body.Bytes(), before, after)
	assert.Equal(t, `attachment; filename="user-42-`+exportedAt.UTC().Format("2006-01-02")+`.json"`,
		rr.Header().Get("Content-Disposition"))
}

// Nothing secret is in the answer: the user's password hash and OTP seed are seeded, and the raw
// body holds neither.
func TestHandleUserExportGet_TheAnswerHoldsNoSecret(t *testing.T) {
	rr, _ := serveExport(t, exportDatabase(), exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "$2a$10$theseededpasswordhashofana")
	assert.NotContains(t, rr.Body.String(), "the-seeded-otp-secret")
}

// The 200 is gzip-compressed when the request's Accept-Encoding allows gzip, and plain JSON
// otherwise (decision 5), read as RFC 9110 section 12.5.3 reads the field: a coding with q=0 is not
// acceptable, "*" stands for any coding the field does not name, and section 8.4.1.3's x-gzip is
// gzip.
func TestHandleUserExportGet_GzipWhenTheCallerAcceptsIt(t *testing.T) {
	for _, c := range []struct {
		name           string
		acceptEncoding []string
		gzip           bool
	}{
		{"no field", nil, false},
		{"gzip", []string{"gzip"}, true},
		{"the field Go's client sends", []string{"gzip, deflate, br"}, true},
		{"gzip in capitals", []string{"GZIP"}, true},
		{"x-gzip", []string{"x-gzip"}, true},
		{"gzip with a weight", []string{"br;q=1.0, gzip;q=0.5"}, true},
		{"gzip with a spaced weight", []string{"gzip ; q=0.8"}, true},
		{"gzip refused", []string{"gzip;q=0"}, false},
		{"gzip refused with three decimals", []string{"gzip;q=0.000"}, false},
		{"any coding", []string{"*"}, true},
		{"any coding refused", []string{"*;q=0"}, false},
		{"gzip refused beside any coding", []string{"*, gzip;q=0"}, false},
		{"any coding refused beside gzip", []string{"gzip, *;q=0"}, true},
		{"identity alone", []string{"identity"}, false},
		{"another coding", []string{"br, deflate"}, false},
		{"empty", []string{""}, false},
		{"gzip on a second field line", []string{"br", "gzip"}, true},
		{"a weight that is not a number", []string{"gzip;q=high"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := time.Now()

			rr, _ := serveExport(t, exportDatabase(), exportRequest("42", c.acceptEncoding...))

			after := time.Now()
			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			assert.Equal(t, []string{"Accept-Encoding"}, rr.Header().Values("Vary"))
			body := rr.Body.Bytes()
			if c.gzip {
				assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
				reader, err := gzip.NewReader(bytes.NewReader(body))
				require.NoError(t, err, "the body is gzip")
				body, err = io.ReadAll(reader)
				require.NoError(t, err)
			} else {
				assert.Empty(t, rr.Header().Get("Content-Encoding"))
			}
			assertTheFixtureDocument(t, body, before, after)
		})
	}
}

// The answer has five minutes to reach the caller instead of the listener's 60 seconds, so a slow
// connection still receives a large file (decision 5).
func TestHandleUserExportGet_LiftsTheWriteDeadlineToFiveMinutes(t *testing.T) {
	before := time.Now()

	rr, _ := serveExport(t, exportDatabase(), exportRequest("42"))

	after := time.Now()
	require.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, rr.deadlines, 1)
	assert.False(t, rr.deadlines[0].Before(before.Add(5*time.Minute)) || rr.deadlines[0].After(after.Add(5*time.Minute)),
		"the deadline %v is not five minutes after the request", rr.deadlines[0])
}

// A writer that takes no deadline, as no listener's does, still answers the export.
func TestHandleUserExportGet_AWriterWithNoDeadlineStillAnswers(t *testing.T) {
	rr := httptest.NewRecorder()
	auditLogger := &exportAudit{recorder: rr}

	HandleUserExportGet(exportDatabase(), auditLogger).ServeHTTP(rr, exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code)
	assertTheFixtureDocument(t, rr.Body.Bytes(), time.Now().Add(-time.Minute), time.Now())
	assert.Len(t, auditLogger.events, 1)
}

// An export writes exported_user_data naming the user exported and who asked, once the answer has
// been written (decision 8).
func TestHandleUserExportGet_RecordsTheExportAfterTheAnswer(t *testing.T) {
	for _, acceptEncoding := range []string{"", "gzip"} {
		t.Run("Accept-Encoding "+acceptEncoding, func(t *testing.T) {
			rr, auditLogger := serveExport(t, exportDatabase(), exportRequest("42", acceptEncoding))

			require.Equal(t, http.StatusOK, rr.Code)
			require.Len(t, auditLogger.events, 1)
			event := auditLogger.events[0]
			assert.Equal(t, "exported_user_data", event.event)
			assert.Equal(t, map[string]interface{}{
				"user_id":        int64(42),
				"logged_in_user": "the-administrator",
			}, event.details)
			assert.Equal(t, rr.Body.Len(), event.bodyWritten, "the event is written once the whole answer is")
		})
	}
}

// A refused or failed export answers the API's error envelope, uncompressed whatever the caller
// accepts, and records nothing.
func TestHandleUserExportGet_RefusalsAndFailuresAreUncompressedAndUnrecorded(t *testing.T) {
	for _, c := range []struct {
		name     string
		id       string
		database *userExportUsers
		status   int
		code     string
	}{
		{"an id that is not a number", "abc", exportDatabase(), http.StatusBadRequest, "VALIDATION_ERROR"},
		{"an id that names no user", "43", exportDatabase(), http.StatusNotFound, "NOT_FOUND"},
		{"a failed read", "42", &userExportUsers{err: errs.New("the database is down")}, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
	} {
		t.Run(c.name, func(t *testing.T) {
			logtest.CaptureSlog(t)

			rr, auditLogger := serveExport(t, c.database, exportRequest(c.id, "gzip"))

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

// The issuer comes from the request's settings; a request that carries none is a wiring fault,
// answered as the API's 500 and recorded nowhere.
func TestHandleUserExportGet_NoSettingsIsAFiveHundred(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/42/export", nil)
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": "the-administrator"})
	r = withPathValue(r, "id", "42")

	rr, auditLogger := serveExport(t, exportDatabase(), r)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Empty(t, auditLogger.events)
	assert.Len(t, capture.Records(), 1)
}
