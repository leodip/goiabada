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
		61: {{UserSessionId: 61, ClientId: 101}, {UserSessionId: 61, ClientId: 100}},
		60: {{UserSessionId: 60, ClientId: 100}},
		62: {{UserSessionId: 62, ClientId: 100}},
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
// order, the expired session left out, and the picture as its content type and base64 bytes. The
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
			"clientIdentifiers": ["forum", "shop"], "clients": [
				{"clientIdentifier": "forum", "name": "forum", "nameUnverified": false},
				{"clientIdentifier": "shop", "name": "Shop", "nameUnverified": false}]}
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
		"GetUserProfilePictureByUserId",
	} {
		t.Run(read, func(t *testing.T) {
			logtest.CaptureSlog(t)
			database := exportEverythingDatabase(time.Now().UTC())
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
}
