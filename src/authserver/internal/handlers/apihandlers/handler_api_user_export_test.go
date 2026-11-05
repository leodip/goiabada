package apihandlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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

// userExportStore is the endpoint's port, implemented directly: one user's rows as the database
// answers them, in the order given, which is not id order, and the read that fails, if any.
type userExportStore struct {
	users            map[int64]*record.User
	attributes       []record.UserAttribute
	groups           []record.Group
	groupAttributes  map[int64][]record.GroupAttribute
	groupPermissions map[int64][]record.Permission
	memberCounts     map[int64]int
	permissions      []record.Permission
	resources        map[int64]record.Resource
	consents         []record.UserConsent
	clients          map[int64]record.Client
	sessions         []record.UserSession
	sessionClients   map[int64][]record.UserSessionClient
	acceptances      []record.LegalDocumentAcceptance
	legalDocuments   []record.LegalDocument
	legalVersions    map[int64][]record.LegalDocumentVersion
	picture          *record.UserProfilePicture
	refreshTokens    []record.RefreshToken
	codes            map[int64]record.Code
	revokedFamilies  map[string]bool
	auditLogs        []record.AuditLog

	// failing names the one read that answers err; "" for none, "*" for every read.
	failing string
	err     error
	// reads is the user id each read about the user was given, by the read's name.
	reads map[string][]int64
}

func (d *userExportStore) read(name string, userId int64) error {
	if d.reads == nil {
		d.reads = map[string][]int64{}
	}
	d.reads[name] = append(d.reads[name], userId)
	if d.failing == name || d.failing == "*" {
		return d.err
	}
	return nil
}

func (d *userExportStore) GetUserById(_ context.Context, _ *sql.Tx, userId int64) (*record.User, error) {
	if err := d.read("GetUserById", userId); err != nil {
		return nil, err
	}
	user, ok := d.users[userId]
	if !ok {
		return nil, nil
	}
	copied := *user
	return &copied, nil
}

func (d *userExportStore) GetUserAttributesByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]record.UserAttribute, error) {
	if err := d.read("GetUserAttributesByUserId", userId); err != nil {
		return nil, err
	}
	return slices.Clone(d.attributes), nil
}

func (d *userExportStore) UserLoadGroups(_ context.Context, _ *sql.Tx, user *record.User) error {
	if err := d.read("UserLoadGroups", user.Id); err != nil {
		return err
	}
	user.Groups = slices.Clone(d.groups)
	return nil
}

func (d *userExportStore) CountGroupMembers(_ context.Context, _ *sql.Tx, groupId int64) (int, error) {
	if err := d.read("CountGroupMembers", 0); err != nil {
		return 0, err
	}
	return d.memberCounts[groupId], nil
}

func (d *userExportStore) GetGroupAttributesByGroupId(_ context.Context, _ *sql.Tx, groupId int64) ([]record.GroupAttribute, error) {
	if err := d.read("GetGroupAttributesByGroupId", 0); err != nil {
		return nil, err
	}
	return slices.Clone(d.groupAttributes[groupId]), nil
}

func (d *userExportStore) GroupLoadPermissions(_ context.Context, _ *sql.Tx, group *record.Group) error {
	if err := d.read("GroupLoadPermissions", 0); err != nil {
		return err
	}
	group.Permissions = slices.Clone(d.groupPermissions[group.Id])
	return nil
}

func (d *userExportStore) UserLoadPermissions(_ context.Context, _ *sql.Tx, user *record.User) error {
	if err := d.read("UserLoadPermissions", user.Id); err != nil {
		return err
	}
	user.Permissions = slices.Clone(d.permissions)
	return nil
}

func (d *userExportStore) GetResourceById(_ context.Context, _ *sql.Tx, resourceId int64) (*record.Resource, error) {
	if err := d.read("GetResourceById", 0); err != nil {
		return nil, err
	}
	resource, ok := d.resources[resourceId]
	if !ok {
		return nil, nil
	}
	return &resource, nil
}

func (d *userExportStore) GetConsentsByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]record.UserConsent, error) {
	if err := d.read("GetConsentsByUserId", userId); err != nil {
		return nil, err
	}
	return slices.Clone(d.consents), nil
}

func (d *userExportStore) UserConsentsLoadClients(_ context.Context, _ *sql.Tx, userConsents []record.UserConsent) error {
	if err := d.read("UserConsentsLoadClients", 0); err != nil {
		return err
	}
	for i := range userConsents {
		userConsents[i].Client = d.clients[userConsents[i].ClientId]
	}
	return nil
}

func (d *userExportStore) GetUserSessionsByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]record.UserSession, error) {
	if err := d.read("GetUserSessionsByUserId", userId); err != nil {
		return nil, err
	}
	return slices.Clone(d.sessions), nil
}

func (d *userExportStore) UserSessionsLoadClients(_ context.Context, _ *sql.Tx, userSessions []record.UserSession) error {
	if err := d.read("UserSessionsLoadClients", 0); err != nil {
		return err
	}
	for i := range userSessions {
		userSessions[i].Clients = slices.Clone(d.sessionClients[userSessions[i].Id])
	}
	return nil
}

func (d *userExportStore) GetClientsByIds(_ context.Context, _ *sql.Tx, clientIds []int64) ([]record.Client, error) {
	if err := d.read("GetClientsByIds", 0); err != nil {
		return nil, err
	}
	clients := make([]record.Client, 0, len(clientIds))
	for _, id := range clientIds {
		if client, ok := d.clients[id]; ok {
			clients = append(clients, client)
		}
	}
	return clients, nil
}

func (d *userExportStore) GetLegalDocumentAcceptancesByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]record.LegalDocumentAcceptance, error) {
	if err := d.read("GetLegalDocumentAcceptancesByUserId", userId); err != nil {
		return nil, err
	}
	return slices.Clone(d.acceptances), nil
}

func (d *userExportStore) GetAllLegalDocuments(_ context.Context, _ *sql.Tx) ([]record.LegalDocument, error) {
	if err := d.read("GetAllLegalDocuments", 0); err != nil {
		return nil, err
	}
	return slices.Clone(d.legalDocuments), nil
}

func (d *userExportStore) GetLegalDocumentVersionsByLegalDocumentId(_ context.Context, _ *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error) {
	if err := d.read("GetLegalDocumentVersionsByLegalDocumentId", 0); err != nil {
		return nil, err
	}
	return slices.Clone(d.legalVersions[legalDocumentId]), nil
}

func (d *userExportStore) GetUserProfilePictureByUserId(_ context.Context, _ *sql.Tx, userId int64) (*record.UserProfilePicture, error) {
	if err := d.read("GetUserProfilePictureByUserId", userId); err != nil {
		return nil, err
	}
	return d.picture, nil
}

func (d *userExportStore) GetRefreshTokensByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]*record.RefreshToken, error) {
	if err := d.read("GetRefreshTokensByUserId", userId); err != nil {
		return nil, err
	}
	tokens := make([]*record.RefreshToken, 0, len(d.refreshTokens))
	for i := range d.refreshTokens {
		copied := d.refreshTokens[i]
		tokens = append(tokens, &copied)
	}
	return tokens, nil
}

func (d *userExportStore) GetCodeById(_ context.Context, _ *sql.Tx, codeId int64) (*record.Code, error) {
	if err := d.read("GetCodeById", codeId); err != nil {
		return nil, err
	}
	code, ok := d.codes[codeId]
	if !ok {
		return nil, nil
	}
	return &code, nil
}

func (d *userExportStore) IsRefreshTokenFamilyRevoked(_ context.Context, _ *sql.Tx, firstRefreshTokenJti string) (bool, error) {
	if err := d.read("IsRefreshTokenFamilyRevoked", 0); err != nil {
		return false, err
	}
	return d.revokedFamilies[firstRefreshTokenJti], nil
}

func (d *userExportStore) GetAuditLogsByUserId(_ context.Context, _ *sql.Tx, userId int64) ([]record.AuditLog, error) {
	if err := d.read("GetAuditLogsByUserId", userId); err != nil {
		return nil, err
	}
	return slices.Clone(d.auditLogs), nil
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
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{
		Issuer:                          "https://auth.example.com",
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
	}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": "the-administrator"})
	return withPathValue(r, "id", id)
}

func serveExport(t *testing.T, database *userExportStore, r *http.Request) (*deadlineRecorder, *exportAudit) {
	t.Helper()
	rr := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	auditLogger := &exportAudit{recorder: rr.ResponseRecorder}
	HandleUserExportGet(database, auditLogger, "https://auth.example.com").ServeHTTP(rr, r)
	return rr, auditLogger
}

// exportDatabase holds the fixture user and nothing else about them.
func exportDatabase() *userExportStore {
	return &userExportStore{users: map[int64]*record.User{42: exportFixtureUser()}}
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
	assert.Equal(t, []int64{42}, database.reads["GetUserById"])
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

	HandleUserExportGet(exportDatabase(), auditLogger, "https://auth.example.com").ServeHTTP(rr, exportRequest("42"))

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

// interruptedWriter is a connection that takes the first half of the answer, then breaks.
type interruptedWriter struct{ *httptest.ResponseRecorder }

func (w *interruptedWriter) Write(p []byte) (int, error) {
	n, _ := w.ResponseRecorder.Write(p[:len(p)/2])
	return n, io.ErrClosedPipe
}

// An answer the caller did not receive whole is still recorded: part of the data has left the
// server either way (decision 8).
func TestHandleUserExportGet_RecordsAnExportTheCallerDidNotReceiveWhole(t *testing.T) {
	for _, acceptEncoding := range []string{"", "gzip"} {
		t.Run("Accept-Encoding "+acceptEncoding, func(t *testing.T) {
			rr := httptest.NewRecorder()
			auditLogger := &exportAudit{recorder: rr}

			HandleUserExportGet(exportDatabase(), auditLogger, "https://auth.example.com").ServeHTTP(
				&interruptedWriter{rr}, exportRequest("42", acceptEncoding))

			require.Positive(t, rr.Body.Len(), "part of the document left the server")
			require.Len(t, auditLogger.events, 1)
			assert.Equal(t, "exported_user_data", auditLogger.events[0].event)
			assert.Equal(t, map[string]interface{}{
				"user_id":        int64(42),
				"logged_in_user": "the-administrator",
			}, auditLogger.events[0].details)
		})
	}
}

// A refused or failed export answers the API's error envelope, uncompressed whatever the caller
// accepts, and records nothing.
func TestHandleUserExportGet_RefusalsAndFailuresAreUncompressedAndUnrecorded(t *testing.T) {
	for _, c := range []struct {
		name     string
		id       string
		database *userExportStore
		status   int
		code     string
	}{
		{"an id that is not a number", "abc", exportDatabase(), http.StatusBadRequest, "VALIDATION_ERROR"},
		{"an id that names no user", "43", exportDatabase(), http.StatusNotFound, "NOT_FOUND"},
		{"a failed read", "42", &userExportStore{failing: "*", err: errs.New("the database is down")}, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
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

// The secrets a seeded client carries, which no part of the document may copy.
const exportSeededClientSecret = "the-seeded-client-secret-ciphertext"

// exportEverythingDatabase holds the fixture user with one or more of each part the admin API
// reads about a user: attributes, two groups (one with attributes and permissions of its own, one
// with none), direct permissions, consents, two live sessions and one past its idle timeout, three
// legal document acceptances (one of a retired document) and a profile picture. Every list is
// answered out of id order, as nothing promises the reads' order. The sessions are timed from now.
func exportEverythingDatabase(now time.Time) *userExportStore {
	at := func(s string) sql.NullTime {
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return sql.NullTime{Time: parsed, Valid: true}
	}
	instant := func(s string) time.Time { return at(s).Time }
	store := exportDatabase()

	store.attributes = []record.UserAttribute{
		{Id: 12, CreatedAt: at("2025-03-01T10:00:00Z"), Key: "department", Value: "Sales", IncludeInIdToken: true, UserId: 42},
		{Id: 11, CreatedAt: at("2025-02-01T10:00:00Z"), Key: "employee_number", Value: "E-1001", IncludeInAccessToken: true, UserId: 42},
	}

	store.groups = []record.Group{
		{Id: 8, GroupIdentifier: "auditors", Description: "Auditors", IncludeInIdToken: true},
		{Id: 5, CreatedAt: at("2025-01-10T09:00:00Z"), GroupIdentifier: "sales", Description: "Sales team", IncludeInAccessToken: true},
	}
	store.memberCounts = map[int64]int{5: 3, 8: 1}
	store.groupAttributes = map[int64][]record.GroupAttribute{
		5: {
			{Id: 31, Key: "region", Value: "south", IncludeInIdToken: true, GroupId: 5},
			{Id: 30, Key: "floor", Value: "2", GroupId: 5},
		},
	}
	store.groupPermissions = map[int64][]record.Permission{
		5: {
			{Id: 21, PermissionIdentifier: "orders:write", Description: "Write orders", ResourceId: 3},
			{Id: 20, PermissionIdentifier: "orders:read", Description: "Read orders", ResourceId: 3},
		},
	}
	store.permissions = []record.Permission{
		{Id: 23, PermissionIdentifier: "manage-users", Description: "Manage users", ResourceId: 4},
		{Id: 22, PermissionIdentifier: "orders:export", Description: "Export orders", ResourceId: 3},
	}
	store.resources = map[int64]record.Resource{
		3: {Id: 3, ResourceIdentifier: "orders-api", Description: "Orders API"},
		4: {Id: 4, ResourceIdentifier: "authserver", Description: "Authserver"},
	}

	store.clients = map[int64]record.Client{
		100: {Id: 100, ClientIdentifier: "shop", Description: "The shop", DisplayName: "Shop", ShowDisplayName: true,
			ClientSecretEncrypted: []byte(exportSeededClientSecret)},
		101: {Id: 101, ClientIdentifier: "forum", Description: "Forum app",
			ClientSecretEncrypted: []byte(exportSeededClientSecret)},
	}
	store.consents = []record.UserConsent{
		{Id: 41, UserId: 42, ClientId: 101, Scope: "openid email", GrantedAt: at("2026-02-01T08:00:00Z")},
		{Id: 40, UserId: 42, ClientId: 100, Scope: "openid profile", GrantedAt: at("2026-01-01T08:00:00Z")},
	}

	store.sessions = []record.UserSession{
		{Id: 62, SessionIdentifier: "sid-62", Started: now.Add(-48 * time.Hour), LastAccessed: now.Add(-47 * time.Hour),
			AuthTime: now.Add(-48 * time.Hour), AuthMethods: "pwd", AcrLevel: record.AcrLevel1, IpAddress: "192.0.2.9", UserId: 42},
		{Id: 61, SessionIdentifier: "sid-61", Started: now.Add(-time.Hour), LastAccessed: now.Add(-10 * time.Minute),
			AuthTime: now.Add(-time.Hour), AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory, IpAddress: "203.0.113.7",
			DeviceName: "Firefox", DeviceType: "desktop", DeviceOS: "Linux", UserAgent: "Mozilla/5.0 (X11)", UserId: 42},
		{Id: 60, SessionIdentifier: "sid-60", Started: now.Add(-2 * time.Hour), LastAccessed: now.Add(-20 * time.Minute),
			AuthTime: now.Add(-2 * time.Hour), AuthMethods: "pwd", AcrLevel: record.AcrLevel1, IpAddress: "198.51.100.4",
			DeviceName: "Safari", DeviceType: "mobile", DeviceOS: "iOS", UserAgent: "Mozilla/5.0 (iPhone)", UserId: 42},
	}
	store.sessionClients = map[int64][]record.UserSessionClient{
		// Session 61's forum association is the later one, answered first.
		61: {{Id: 802, UserSessionId: 61, ClientId: 101}, {Id: 801, UserSessionId: 61, ClientId: 100}},
		60: {{Id: 800, UserSessionId: 60, ClientId: 100}},
		62: {{Id: 803, UserSessionId: 62, ClientId: 100}},
	}

	// The database answers acceptances in the order they were stored; AcceptedBy turns them the
	// latest first.
	store.acceptances = []record.LegalDocumentAcceptance{
		{Id: 70, AcceptedAt: instant("2025-01-02T00:00:00Z"), UserId: 42, LegalDocumentVersionId: 900},
		{Id: 71, AcceptedAt: instant("2025-05-02T00:00:00Z"), UserId: 42, LegalDocumentVersionId: 910},
		{Id: 72, AcceptedAt: instant("2026-01-02T00:00:00Z"), UserId: 42, LegalDocumentVersionId: 901},
	}
	store.legalDocuments = []record.LegalDocument{
		{Id: 90, ShortName: "terms"},
		{Id: 91, ShortName: "house-rules", RetiredAt: at("2026-06-01T00:00:00Z")},
	}
	store.legalVersions = map[int64][]record.LegalDocumentVersion{
		90: {
			{Id: 900, PublishedAt: instant("2025-01-01T00:00:00Z"), LegalDocumentId: 90, VersionNumber: 1, Title: "Terms of use"},
			{Id: 901, PublishedAt: instant("2026-01-01T00:00:00Z"), LegalDocumentId: 90, VersionNumber: 2, Title: "Terms of use, revised"},
		},
		91: {
			{Id: 910, PublishedAt: instant("2025-05-01T00:00:00Z"), LegalDocumentId: 91, VersionNumber: 1, Title: "House rules"},
		},
	}

	// The first four bytes of a PNG: 89 50 4e 47, which is iVBORw== in base64.
	store.picture = &record.UserProfilePicture{Id: 3, UserId: 42, ContentType: "image/png", Picture: []byte{0x89, 'P', 'N', 'G'}}
	return store
}

// exportEverythingParts is what the document holds for exportEverythingDatabase beside the user,
// written out by hand: each entry as the matching admin API read answers it, every list in id
// order, a session's apps by their association's, the expired session left out, and the picture as its content type and base64 bytes. The
// four %s are the live sessions' times: session 60's start and last access, then session 61's.
const exportEverythingParts = `{
	"attributes": [
		{"id": 11, "createdAt": "2025-02-01T10:00:00Z", "updatedAt": null, "key": "employee_number",
			"value": "E-1001", "includeInIdToken": false, "includeInAccessToken": true, "userId": 42},
		{"id": 12, "createdAt": "2025-03-01T10:00:00Z", "updatedAt": null, "key": "department",
			"value": "Sales", "includeInIdToken": true, "includeInAccessToken": false, "userId": 42}
	],
	"groups": [
		{"id": 5, "createdAt": "2025-01-10T09:00:00Z", "updatedAt": null, "groupIdentifier": "sales",
			"description": "Sales team", "includeInIdToken": false, "includeInAccessToken": true, "memberCount": 3,
			"attributes": [
				{"id": 30, "createdAt": null, "updatedAt": null, "key": "floor", "value": "2",
					"includeInIdToken": false, "includeInAccessToken": false, "groupId": 5},
				{"id": 31, "createdAt": null, "updatedAt": null, "key": "region", "value": "south",
					"includeInIdToken": true, "includeInAccessToken": false, "groupId": 5}
			],
			"permissions": [
				{"id": 20, "permissionIdentifier": "orders:read", "description": "Read orders", "resourceId": 3,
					"resource": {"id": 3, "resourceIdentifier": "orders-api", "description": "Orders API", "isSystemLevelResource": false}},
				{"id": 21, "permissionIdentifier": "orders:write", "description": "Write orders", "resourceId": 3,
					"resource": {"id": 3, "resourceIdentifier": "orders-api", "description": "Orders API", "isSystemLevelResource": false}}
			]},
		{"id": 8, "createdAt": null, "updatedAt": null, "groupIdentifier": "auditors",
			"description": "Auditors", "includeInIdToken": true, "includeInAccessToken": false, "memberCount": 1,
			"attributes": [], "permissions": []}
	],
	"permissions": [
		{"id": 22, "permissionIdentifier": "orders:export", "description": "Export orders", "resourceId": 3,
			"resource": {"id": 3, "resourceIdentifier": "orders-api", "description": "Orders API", "isSystemLevelResource": false}},
		{"id": 23, "permissionIdentifier": "manage-users", "description": "Manage users", "resourceId": 4,
			"resource": {"id": 4, "resourceIdentifier": "authserver", "description": "Authserver", "isSystemLevelResource": true}}
	],
	"consents": [
		{"id": 40, "createdAt": null, "updatedAt": null, "clientId": 100, "userId": 42, "scope": "openid profile",
			"grantedAt": "2026-01-01T08:00:00Z", "clientIdentifier": "shop", "clientName": "Shop",
			"clientNameUnverified": false, "clientDescription": "The shop"},
		{"id": 41, "createdAt": null, "updatedAt": null, "clientId": 101, "userId": 42, "scope": "openid email",
			"grantedAt": "2026-02-01T08:00:00Z", "clientIdentifier": "forum", "clientName": "forum",
			"clientNameUnverified": false, "clientDescription": "Forum app"}
	],
	"sessions": [
		{"id": 60, "createdAt": null, "updatedAt": null, "sessionIdentifier": "sid-60", "started": %[1]s,
			"lastAccessed": %[2]s, "authMethods": "pwd", "acrLevel": "urn:goiabada:level1", "authTime": %[1]s,
			"ipAddress": "198.51.100.4", "deviceName": "Safari", "deviceType": "mobile", "deviceOS": "iOS",
			"userAgent": "Mozilla/5.0 (iPhone)", "userId": 42, "isCurrent": false,
			"clientIdentifiers": ["shop"], "clients": [{"clientIdentifier": "shop", "name": "Shop", "nameUnverified": false}]},
		{"id": 61, "createdAt": null, "updatedAt": null, "sessionIdentifier": "sid-61", "started": %[3]s,
			"lastAccessed": %[4]s, "authMethods": "pwd otp", "acrLevel": "urn:goiabada:level2_mandatory", "authTime": %[3]s,
			"ipAddress": "203.0.113.7", "deviceName": "Firefox", "deviceType": "desktop", "deviceOS": "Linux",
			"userAgent": "Mozilla/5.0 (X11)", "userId": 42, "isCurrent": false,
			"clientIdentifiers": ["shop", "forum"], "clients": [
				{"clientIdentifier": "shop", "name": "Shop", "nameUnverified": false},
				{"clientIdentifier": "forum", "name": "forum", "nameUnverified": false}]}
	],
	"legalDocumentAcceptances": [
		{"id": 70, "acceptedAt": "2025-01-02T00:00:00Z", "legalDocumentId": 90, "shortName": "terms", "version": 1,
			"title": "Terms of use", "publishedAt": "2025-01-01T00:00:00Z", "retired": false,
			"url": "https://auth.example.com/legal/terms/versions/1"},
		{"id": 71, "acceptedAt": "2025-05-02T00:00:00Z", "legalDocumentId": 91, "shortName": "house-rules", "version": 1,
			"title": "House rules", "publishedAt": "2025-05-01T00:00:00Z", "retired": true, "url": null},
		{"id": 72, "acceptedAt": "2026-01-02T00:00:00Z", "legalDocumentId": 90, "shortName": "terms", "version": 2,
			"title": "Terms of use, revised", "publishedAt": "2026-01-01T00:00:00Z", "retired": false,
			"url": "https://auth.example.com/legal/terms/versions/2"}
	],
	"profilePicture": {"contentType": "image/png", "data": "iVBORw=="}
}`

// exportedParts is the document's parts that exportEverythingParts describes, out of a plain body.
func exportedParts(t *testing.T, body []byte) string {
	t.Helper()
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &parts), "%q", body)
	picked := map[string]json.RawMessage{}
	for _, key := range []string{"attributes", "groups", "permissions", "consents", "sessions", "legalDocumentAcceptances", "profilePicture"} {
		picked[key] = parts[key]
	}
	out, err := json.Marshal(picked)
	require.NoError(t, err)
	return string(out)
}

// The document holds what the admin API reads about the user, each entry as the matching read
// answers it and every list in id order, oldest first, so two exports of one person compare line
// by line (#781 decision 3). Sessions are the live ones, by the rule GET /users/{id}/sessions
// applies, and none is marked current, even the caller's own: the document is the same whoever asks.
func TestHandleUserExportGet_HoldsWhatTheAdminAPIReadsAboutTheUser(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	database := exportEverythingDatabase(now)
	r := exportRequest("42")
	// The caller's own token names session 61.
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": "the-administrator", "sid": "sid-61"})

	rr, _ := serveExport(t, database, r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	quoted := func(at time.Time) string { return `"` + at.Format(time.RFC3339) + `"` }
	assert.JSONEq(t, fmt.Sprintf(exportEverythingParts,
		quoted(now.Add(-2*time.Hour)), quoted(now.Add(-20*time.Minute)),
		quoted(now.Add(-time.Hour)), quoted(now.Add(-10*time.Minute))),
		exportedParts(t, rr.Body.Bytes()))

	// Every read about the user named this user.
	for _, name := range []string{"GetUserAttributesByUserId", "UserLoadGroups", "UserLoadPermissions", "GetConsentsByUserId",
		"GetUserSessionsByUserId", "GetLegalDocumentAcceptancesByUserId", "GetUserProfilePictureByUserId"} {
		assert.Equal(t, []int64{42}, database.reads[name], name)
	}
}

// Nothing secret reaches the document from the parts either: the clients loaded onto consents and
// sessions carry an encrypted secret, which no mapping copies.
func TestHandleUserExportGet_ThePartsHoldNoSecret(t *testing.T) {
	rr, _ := serveExport(t, exportEverythingDatabase(time.Now().UTC()), exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), exportSeededClientSecret)
	assert.NotContains(t, rr.Body.String(), base64.StdEncoding.EncodeToString([]byte(exportSeededClientSecret)))
	assert.NotContains(t, rr.Body.String(), "$2a$10$theseededpasswordhashofana")
	assert.NotContains(t, rr.Body.String(), "the-seeded-otp-secret")
}

// The handler reads every part before it answers, so a read that fails is the API's clean 500,
// never a document with a part missing, and records nothing (decision 5).
func TestHandleUserExportGet_AFailedReadOfAnyPartIsAFiveHundred(t *testing.T) {
	for _, read := range []string{
		"GetUserAttributesByUserId", "UserLoadGroups", "CountGroupMembers", "GetGroupAttributesByGroupId",
		"GroupLoadPermissions", "UserLoadPermissions", "GetResourceById", "GetConsentsByUserId",
		"UserConsentsLoadClients", "GetUserSessionsByUserId", "UserSessionsLoadClients", "GetClientsByIds",
		"GetLegalDocumentAcceptancesByUserId", "GetAllLegalDocuments", "GetLegalDocumentVersionsByLegalDocumentId",
		"GetUserProfilePictureByUserId", "GetRefreshTokensByUserId", "GetCodeById", "IsRefreshTokenFamilyRevoked",
		"GetAuditLogsByUserId",
	} {
		t.Run(read, func(t *testing.T) {
			logtest.CaptureSlog(t)
			database := exportEverythingDatabase(time.Now().UTC())
			tokens := exportRefreshTokensDatabase()
			database.refreshTokens, database.codes, database.revokedFamilies = tokens.refreshTokens, tokens.codes, tokens.revokedFamilies
			database.clients[102] = tokens.clients[102]
			database.failing, database.err = read, errs.New("the database is down")

			rr, auditLogger := serveExport(t, database, exportRequest("42", "gzip"))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.NotEmpty(t, database.reads[read], "the read was made")
			assert.Empty(t, rr.Header().Get("Content-Encoding"))
			assert.Empty(t, rr.Header().Get("Content-Disposition"))
			var envelope map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope), "a plain JSON envelope: %q", rr.Body.String())
			assert.Equal(t, "INTERNAL_SERVER_ERROR", envelope["error_code"])
			assert.Empty(t, auditLogger.events)
		})
	}
}

// A user with nothing beside the profile has every list empty, never null, and no picture.
func TestHandleUserExportGet_AUserWithNothingElseHasEmptyListsAndNoPicture(t *testing.T) {
	rr, _ := serveExport(t, exportDatabase(), exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"attributes": [], "groups": [], "permissions": [], "consents": [], "sessions": [],
		"legalDocumentAcceptances": [], "profilePicture": null}`, exportedParts(t, rr.Body.Bytes()))
	assert.JSONEq(t, `[]`, exportedPart(t, rr.Body.Bytes(), "refreshTokens"))
}

// exportedPart is one part of the document, out of a plain body.
func exportedPart(t *testing.T, body []byte, key string) string {
	t.Helper()
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &parts), "%q", body)
	return string(parts[key])
}

// The secrets the seeded refresh tokens' codes carry: the code's hash, its PKCE challenge and its
// nonce, none of which is part of a refresh token's entry.
const (
	exportSeededCodeHash      = "the-seeded-code-hash-of-the-authorization-code"
	exportSeededCodeChallenge = "the-seeded-pkce-code-challenge"
	exportSeededCodeNonce     = "the-seeded-nonce"
)

// exportRefreshTokensDatabase holds the fixture user with six refresh token rows, answered out of
// id order: a code-flow grant of the shop's (code 500) rotated once, so its first token is revoked
// as rotated out and its second is live; an offline code-flow token of the forum's (code 501),
// whose own row is live but whose code is marked revoked; a password-grant grant of the command
// line tool's rotated once, its second token issued months after the password was checked; and a
// password-grant token whose own row is live but whose family is recorded as revoked, issued before
// the row recorded when the password was checked.
func exportRefreshTokensDatabase() *userExportStore {
	at := func(s string) sql.NullTime {
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return sql.NullTime{Time: parsed, Valid: true}
	}
	id := func(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }
	store := exportDatabase()

	store.clients = map[int64]record.Client{
		100: {Id: 100, ClientIdentifier: "shop", Description: "The shop", DisplayName: "Shop", ShowDisplayName: true,
			ClientSecretEncrypted: []byte(exportSeededClientSecret)},
		101: {Id: 101, ClientIdentifier: "forum", Description: "Forum app",
			ClientSecretEncrypted: []byte(exportSeededClientSecret)},
		// A client that registered itself: the name it gave is its own claim.
		102: {Id: 102, ClientIdentifier: "cli-tool", Description: "Ana's command line", CreatedViaDCR: true,
			ClientSecretEncrypted: []byte(exportSeededClientSecret)},
	}
	store.codes = map[int64]record.Code{
		500: {Id: 500, CodeHash: exportSeededCodeHash, ClientId: 100, Scope: "openid profile email",
			CodeChallenge: sql.NullString{String: exportSeededCodeChallenge, Valid: true}, Nonce: exportSeededCodeNonce,
			UserId: 42, IpAddress: "203.0.113.7", UserAgent: "Mozilla/5.0 (X11)",
			AuthenticatedAt: at("2026-10-01T09:00:00Z").Time, SessionIdentifier: "sid-61", Used: true},
		501: {Id: 501, CodeHash: exportSeededCodeHash, ClientId: 101, Scope: "openid offline_access",
			UserId: 42, IpAddress: "198.51.100.4", UserAgent: "Mozilla/5.0 (iPhone)",
			AuthenticatedAt: at("2026-09-01T08:00:00Z").Time, SessionIdentifier: "sid-60", Used: true, Revoked: true},
	}
	store.revokedFamilies = map[string]bool{"jti-84": true}
	store.refreshTokens = []record.RefreshToken{
		{Id: 86, UserId: id(42), ClientId: id(102), RefreshTokenJti: "jti-86", PreviousRefreshTokenJti: "jti-83",
			FirstRefreshTokenJti: "jti-83", RefreshTokenType: "Offline", Scope: "openid offline_access",
			IssuedAt: at("2026-10-15T07:00:00Z"), ExpiresAt: at("2026-11-14T07:00:00Z"), MaxLifetime: at("2027-08-01T07:00:00Z"),
			AuthenticatedAt: at("2026-08-01T07:00:00Z")},
		{Id: 81, CodeId: id(500), RefreshTokenJti: "jti-81", FirstRefreshTokenJti: "jti-81", SessionIdentifier: "sid-61",
			RefreshTokenType: "Refresh", Scope: "openid profile email",
			IssuedAt: at("2026-10-01T09:00:05Z"), ExpiresAt: at("2026-10-01T11:00:05Z"), Revoked: true},
		{Id: 85, CodeId: id(501), RefreshTokenJti: "jti-85", FirstRefreshTokenJti: "jti-85",
			RefreshTokenType: "Offline", Scope: "openid offline_access",
			IssuedAt: at("2026-09-01T08:00:02Z"), ExpiresAt: at("2026-10-01T08:00:02Z"), MaxLifetime: at("2027-09-01T08:00:02Z")},
		{Id: 83, UserId: id(42), ClientId: id(102), RefreshTokenJti: "jti-83", FirstRefreshTokenJti: "jti-83",
			RefreshTokenType: "Offline", Scope: "openid offline_access",
			IssuedAt: at("2026-08-01T07:00:00Z"), ExpiresAt: at("2026-08-31T07:00:00Z"), MaxLifetime: at("2027-08-01T07:00:00Z"),
			Revoked: true, AuthenticatedAt: at("2026-08-01T07:00:00Z")},
		{Id: 84, UserId: id(42), ClientId: id(102), RefreshTokenJti: "jti-84", FirstRefreshTokenJti: "jti-84",
			RefreshTokenType: "Offline", Scope: "openid",
			IssuedAt: at("2025-06-01T07:00:00Z"), ExpiresAt: at("2025-07-01T07:00:00Z"), MaxLifetime: at("2026-06-01T07:00:00Z")},
		{Id: 82, CodeId: id(500), RefreshTokenJti: "jti-82", PreviousRefreshTokenJti: "jti-81", FirstRefreshTokenJti: "jti-81",
			SessionIdentifier: "sid-61", RefreshTokenType: "Refresh", Scope: "openid profile",
			IssuedAt: at("2026-10-01T10:00:00Z"), ExpiresAt: at("2026-10-01T12:00:00Z")},
	}
	return store
}

// exportRefreshTokens is the document's refreshTokens for exportRefreshTokensDatabase, written out
// by hand from decision 4. In id order: 81 and 82 carry the shop's sign-in from code 500, 81
// revoked by its own row; 83 and 86 are the password grant's, with no sign-in address or browser
// and the time the password was checked, which 86 keeps from 83 though it was issued later; 84 is
// revoked by its family and has no sign-in time stored; 85 is revoked by its code, and as an
// offline token has a maximum lifetime and no session.
const exportRefreshTokens = `[
	{"clientIdentifier": "shop", "clientName": "Shop", "clientNameUnverified": false, "scope": "openid profile email",
		"type": "Refresh", "issuedAt": "2026-10-01T09:00:05Z", "expiresAt": "2026-10-01T11:00:05Z", "maxLifetime": null,
		"sessionIdentifier": "sid-61", "jti": "jti-81", "revoked": true,
		"ipAddress": "203.0.113.7", "userAgent": "Mozilla/5.0 (X11)", "authenticatedAt": "2026-10-01T09:00:00Z"},
	{"clientIdentifier": "shop", "clientName": "Shop", "clientNameUnverified": false, "scope": "openid profile",
		"type": "Refresh", "issuedAt": "2026-10-01T10:00:00Z", "expiresAt": "2026-10-01T12:00:00Z", "maxLifetime": null,
		"sessionIdentifier": "sid-61", "jti": "jti-82", "revoked": false,
		"ipAddress": "203.0.113.7", "userAgent": "Mozilla/5.0 (X11)", "authenticatedAt": "2026-10-01T09:00:00Z"},
	{"clientIdentifier": "cli-tool", "clientName": "Ana's command line", "clientNameUnverified": true, "scope": "openid offline_access",
		"type": "Offline", "issuedAt": "2026-08-01T07:00:00Z", "expiresAt": "2026-08-31T07:00:00Z", "maxLifetime": "2027-08-01T07:00:00Z",
		"sessionIdentifier": "", "jti": "jti-83", "revoked": true,
		"ipAddress": "", "userAgent": "", "authenticatedAt": "2026-08-01T07:00:00Z"},
	{"clientIdentifier": "cli-tool", "clientName": "Ana's command line", "clientNameUnverified": true, "scope": "openid",
		"type": "Offline", "issuedAt": "2025-06-01T07:00:00Z", "expiresAt": "2025-07-01T07:00:00Z", "maxLifetime": "2026-06-01T07:00:00Z",
		"sessionIdentifier": "", "jti": "jti-84", "revoked": true,
		"ipAddress": "", "userAgent": "", "authenticatedAt": null},
	{"clientIdentifier": "forum", "clientName": "forum", "clientNameUnverified": false, "scope": "openid offline_access",
		"type": "Offline", "issuedAt": "2026-09-01T08:00:02Z", "expiresAt": "2026-10-01T08:00:02Z", "maxLifetime": "2027-09-01T08:00:02Z",
		"sessionIdentifier": "", "jti": "jti-85", "revoked": true,
		"ipAddress": "198.51.100.4", "userAgent": "Mozilla/5.0 (iPhone)", "authenticatedAt": "2026-09-01T08:00:00Z"},
	{"clientIdentifier": "cli-tool", "clientName": "Ana's command line", "clientNameUnverified": true, "scope": "openid offline_access",
		"type": "Offline", "issuedAt": "2026-10-15T07:00:00Z", "expiresAt": "2026-11-14T07:00:00Z", "maxLifetime": "2027-08-01T07:00:00Z",
		"sessionIdentifier": "", "jti": "jti-86", "revoked": false,
		"ipAddress": "", "userAgent": "", "authenticatedAt": "2026-08-01T07:00:00Z"}
]`

// The document lists every refresh token row the auth server holds for the user, rotated-out and
// revoked ones included, in id order (#781 decision 4). A token is revoked when its own row, its
// authorization code or its rotation family is marked revoked. Its sign-in's address and browser
// come from its code, and are empty for a password-grant token, which has none; its sign-in time
// comes from the code, or from a password-grant token's own row, kept through rotation.
func TestHandleUserExportGet_ListsEveryRefreshToken(t *testing.T) {
	database := exportRefreshTokensDatabase()

	rr, _ := serveExport(t, database, exportRequest("42", "gzip"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	reader, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.JSONEq(t, exportRefreshTokens, exportedPart(t, body, "refreshTokens"))
	assert.Equal(t, []int64{42}, database.reads["GetRefreshTokensByUserId"])
	// Each code is read once, however many of its grant's tokens there are.
	assert.ElementsMatch(t, []int64{500, 501}, database.reads["GetCodeById"])
}

// A code-flow token whose code is gone by the time it is read, as when cleanup deleted it between
// the two reads, is still listed, with nothing of the sign-in or the client to tell.
func TestHandleUserExportGet_ARefreshTokenWhoseCodeIsGone(t *testing.T) {
	database := exportRefreshTokensDatabase()
	database.refreshTokens = []record.RefreshToken{{Id: 90, CodeId: sql.NullInt64{Int64: 599, Valid: true},
		RefreshTokenJti: "jti-90", FirstRefreshTokenJti: "jti-90", SessionIdentifier: "sid-9",
		RefreshTokenType: "Refresh", Scope: "openid"}}

	rr, _ := serveExport(t, database, exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `[{"clientIdentifier": "", "clientName": "", "clientNameUnverified": false, "scope": "openid",
		"type": "Refresh", "issuedAt": null, "expiresAt": null, "maxLifetime": null,
		"sessionIdentifier": "sid-9", "jti": "jti-90", "revoked": false,
		"ipAddress": "", "userAgent": "", "authenticatedAt": null}]`, exportedPart(t, rr.Body.Bytes(), "refreshTokens"))
}

// Nothing secret comes with the refresh tokens: their codes carry a hash, a PKCE challenge and a
// nonce, and their clients an encrypted secret, which no entry copies. A refresh token itself is
// never stored, only its jti.
func TestHandleUserExportGet_TheRefreshTokensHoldNoSecret(t *testing.T) {
	rr, _ := serveExport(t, exportRefreshTokensDatabase(), exportRequest("42"))

	require.Equal(t, http.StatusOK, rr.Code)
	for _, secret := range []string{exportSeededCodeHash, exportSeededCodeChallenge, exportSeededCodeNonce,
		exportSeededClientSecret, base64.StdEncoding.EncodeToString([]byte(exportSeededClientSecret))} {
		assert.NotContains(t, rr.Body.String(), secret)
	}
}

// The subject of the administrator, user 7, whose token acted on the fixture user: no part of the
// document may carry it.
const exportAdministratorSubject = "5d1c9e7a-3b2f-4c6d-8e9f-0a1b2c3d4e5f"

// exportAuditEventsDatabase holds the fixture user, Ana (user 42), with eight audit rows, answered
// out of id order: an earlier export by the administrator (user 7); the administrator's change to
// Ana; Ana's change to herself; Ana, as an administrator, changing user 9; a sign-in of Ana's on a
// browser that still carried user 77's session; a change by a client credentials token; a grant by
// the recover command; and the administrator ending one of Ana's sessions, whose session id is
// past what a float64 holds exactly.
func exportAuditEventsDatabase() *userExportStore {
	at := func(s string) time.Time {
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return parsed
	}
	id := func(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }
	store := exportDatabase()
	store.auditLogs = []record.AuditLog{
		{Id: 304, CreatedAt: at("2026-10-04T08:00:00Z"), AuditEvent: "cross_user_session_replaced", RequestId: "req-304",
			Details: `{"client_id":100,"previous_session_identifier":"sid-77","previous_user_id":77,"user_id":42}`,
			UserId:  id(42)},
		{Id: 301, CreatedAt: at("2026-10-01T08:00:00Z"), AuditEvent: "updated_user_details", RequestId: "req-301",
			Details: `{"logged_in_user":"` + exportAdministratorSubject + `","user_id":42}`,
			UserId:  id(42), LoggedInUserId: id(7)},
		{Id: 306, CreatedAt: at("2026-10-06T08:00:00Z"), AuditEvent: "updated_user_permissions", RequestId: "",
			Details: `{"command":"recover","user_id":42}`,
			UserId:  id(42)},
		{Id: 302, CreatedAt: at("2026-10-02T08:00:00Z"), AuditEvent: "updated_user_profile", RequestId: "req-302",
			Details: `{"logged_in_user":"7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b","user_id":42}`,
			UserId:  id(42), LoggedInUserId: id(42)},
		{Id: 300, CreatedAt: at("2026-09-30T08:00:00Z"), AuditEvent: "exported_user_data", RequestId: "req-300",
			Details: `{"logged_in_user":"` + exportAdministratorSubject + `","user_id":42}`,
			UserId:  id(42), LoggedInUserId: id(7)},
		{Id: 305, CreatedAt: at("2026-10-05T08:00:00Z"), AuditEvent: "updated_user_details", RequestId: "req-305",
			Details: `{"logged_in_user":"provisioning-client","user_id":42}`,
			UserId:  id(42)},
		{Id: 303, CreatedAt: at("2026-10-03T08:00:00Z"), AuditEvent: "updated_user_details", RequestId: "req-303",
			Details:        `{"logged_in_user":"7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b","user_id":9}`,
			UserId:         id(9),
			LoggedInUserId: id(42)},
		{Id: 307, CreatedAt: at("2026-10-07T08:00:00Z"), AuditEvent: "deleted_user_session", RequestId: "req-307",
			Details: `{"logged_in_user":"` + exportAdministratorSubject + `","reason":"admin_deleted","user_id":42,"user_session_id":9007199254740993}`,
			UserId:  id(42), LoggedInUserId: id(7)},
	}
	return store
}

// exportAuditEvents is the document's auditEvents for exportAuditEventsDatabase, written out by
// hand from decision 2, in id order. The administrator's three rows (300, 301 and 307) say an
// administrator acted, with no loggedInUserId and no logged_in_user, the rest of their details
// kept to the digit. The sign-in on a shared browser (304) no longer names user 77. Ana's own
// actions keep whom they acted on, herself (302) or user 9 (303). The client (305) and the recover
// command (306) are no person, and stay.
const exportAuditEvents = `[
	{"id": 300, "createdAt": "2026-09-30T08:00:00Z", "auditEvent": "exported_user_data",
		"details": "{\"user_id\":42}", "requestId": "req-300", "userId": 42, "loggedInUserId": null,
		"actedByAdministrator": true},
	{"id": 301, "createdAt": "2026-10-01T08:00:00Z", "auditEvent": "updated_user_details",
		"details": "{\"user_id\":42}", "requestId": "req-301", "userId": 42, "loggedInUserId": null,
		"actedByAdministrator": true},
	{"id": 302, "createdAt": "2026-10-02T08:00:00Z", "auditEvent": "updated_user_profile",
		"details": "{\"logged_in_user\":\"7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b\",\"user_id\":42}", "requestId": "req-302",
		"userId": 42, "loggedInUserId": 42, "actedByAdministrator": false},
	{"id": 303, "createdAt": "2026-10-03T08:00:00Z", "auditEvent": "updated_user_details",
		"details": "{\"logged_in_user\":\"7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b\",\"user_id\":9}", "requestId": "req-303",
		"userId": 9, "loggedInUserId": 42, "actedByAdministrator": false},
	{"id": 304, "createdAt": "2026-10-04T08:00:00Z", "auditEvent": "cross_user_session_replaced",
		"details": "{\"client_id\":100,\"previous_session_identifier\":\"sid-77\",\"user_id\":42}", "requestId": "req-304",
		"userId": 42, "loggedInUserId": null, "actedByAdministrator": false},
	{"id": 305, "createdAt": "2026-10-05T08:00:00Z", "auditEvent": "updated_user_details",
		"details": "{\"logged_in_user\":\"provisioning-client\",\"user_id\":42}", "requestId": "req-305",
		"userId": 42, "loggedInUserId": null, "actedByAdministrator": false},
	{"id": 306, "createdAt": "2026-10-06T08:00:00Z", "auditEvent": "updated_user_permissions",
		"details": "{\"command\":\"recover\",\"user_id\":42}", "requestId": "",
		"userId": 42, "loggedInUserId": null, "actedByAdministrator": false},
	{"id": 307, "createdAt": "2026-10-07T08:00:00Z", "auditEvent": "deleted_user_session",
		"details": "{\"reason\":\"admin_deleted\",\"user_id\":42,\"user_session_id\":9007199254740993}", "requestId": "req-307",
		"userId": 42, "loggedInUserId": null, "actedByAdministrator": true}
]`

// The document lists every audit event about the user or made by them, in id order, each the audit
// log's entry plus actedByAdministrator (#781 decisions 2 and 3). An event another user's token
// made about the user says an administrator acted, without saying who; the other user a sign-in on
// a shared browser ended is not named; the user's own actions keep whom they acted on.
func TestHandleUserExportGet_ListsTheAuditEventsWithoutTheAdministratorsWhoActed(t *testing.T) {
	database := exportAuditEventsDatabase()

	rr, _ := serveExport(t, database, exportRequest("42", "gzip"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	reader, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.JSONEq(t, exportAuditEvents, exportedPart(t, body, "auditEvents"))
	assert.Equal(t, []int64{42}, database.reads["GetAuditLogsByUserId"])

	// Nothing anywhere in the document names the administrator or the other user of the browser.
	assert.NotContains(t, string(body), exportAdministratorSubject)
	assert.NotContains(t, string(body), `"loggedInUserId":7`)
	assert.NotContains(t, string(body), "previous_user_id")
	assert.NotContains(t, string(body), "77,")
}

// A row the export must strip but cannot read as a JSON object is never sent as it is: the export
// is the API's clean 500, and records nothing. A row it need not strip is sent as stored.
func TestHandleUserExportGet_AnAuditRowItCannotStripIsAFiveHundred(t *testing.T) {
	for name, row := range map[string]record.AuditLog{
		"an administrator's": {Id: 1, AuditEvent: "updated_user_details", Details: `not json, ` + exportAdministratorSubject,
			UserId: sql.NullInt64{Int64: 42, Valid: true}, LoggedInUserId: sql.NullInt64{Int64: 7, Valid: true}},
		"a shared browser's": {Id: 1, AuditEvent: "cross_user_session_replaced", Details: `["previous_user_id", 77]`,
			UserId: sql.NullInt64{Int64: 42, Valid: true}},
	} {
		t.Run(name, func(t *testing.T) {
			logtest.CaptureSlog(t)
			database := exportDatabase()
			database.auditLogs = []record.AuditLog{row}

			rr, auditLogger := serveExport(t, database, exportRequest("42"))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.NotContains(t, rr.Body.String(), exportAdministratorSubject)
			assert.Empty(t, auditLogger.events)
		})
	}

	t.Run("a row of the user's own", func(t *testing.T) {
		database := exportDatabase()
		database.auditLogs = []record.AuditLog{{Id: 1, AuditEvent: "updated_user_profile", Details: `not json`,
			UserId: sql.NullInt64{Int64: 42, Valid: true}, LoggedInUserId: sql.NullInt64{Int64: 42, Valid: true}}}

		rr, _ := serveExport(t, database, exportRequest("42"))

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.JSONEq(t, `[{"id": 1, "createdAt": "0001-01-01T00:00:00Z", "auditEvent": "updated_user_profile",
			"details": "not json", "requestId": "", "userId": 42, "loggedInUserId": 42, "actedByAdministrator": false}]`,
			exportedPart(t, rr.Body.Bytes(), "auditEvents"))
	})
}
