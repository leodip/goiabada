package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/uithemes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// settingsSaveTx is the transaction the stubbed settings saves run in, so an expectation on it
// tells a write inside the save's transaction from one made outside any.
var settingsSaveTx = &sql.Tx{}

// settingsRowAsTheRequestLoadedIt answers the save's read under its lock with a copy of the
// settings on the request's context: the row as stored when nothing saved since the request
// loaded it.
func settingsRowAsTheRequestLoadedIt(ctx context.Context, _ *sql.Tx, _ int64) (*record.Settings, error) {
	loaded, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		return nil, errors.New("no settings on the request's context")
	}
	stored := *loaded
	stored.SMTPPasswordEncrypted = bytes.Clone(loaded.SMTPPasswordEncrypted)
	return &stored, nil
}

// expectSettingsSave stubs the transaction of one settings save: the row lock and the read under
// it, on settingsSaveTx, the read answering the row the request loaded. The test stubs the
// UpdateSettings it expects on settingsSaveTx itself.
func expectSettingsSave(database *datamocks.Database) {
	datamocks.ExpectRunInTransaction(database, settingsSaveTx)
	database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, mock.Anything).Return(nil).Once()
	database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, mock.Anything).
		RunAndReturn(settingsRowAsTheRequestLoadedIt).Once()
}

// allowSettingsSave is expectSettingsSave for a helper whose cases answer before the save as often
// as they reach it, so none of the three is required.
func allowSettingsSave(database *datamocks.Database) {
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error { return fn(settingsSaveTx) }).Maybe()
	database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, mock.Anything).Return(nil).Maybe()
	database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, mock.Anything).
		RunAndReturn(settingsRowAsTheRequestLoadedIt).Maybe()
}

// settingsSectionSave is one of the seven settings writes, with a body its handler accepts and the
// columns that section owns.
type settingsSectionSave struct {
	name    string
	path    string
	body    func(t *testing.T) string
	handler func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler
	owns    []string
}

func settingsSectionSaves() []settingsSectionSave {
	return []settingsSectionSave{
		{
			name: "general",
			path: "/api/v1/admin/settings/general",
			body: func(*testing.T) string {
				return `{"appName":"Mine","issuer":"https://before.example","passwordPolicy":"medium",` +
					`"selfRegistrationEnabled":false,"pkceRequired":false}`
			},
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsGeneralPut(database, auditLogger, "http://localhost:9090")
			},
			owns: []string{"AppName", "Issuer", "SelfRegistrationEnabled", "SelfRegistrationRequiresEmailVerification",
				"DynamicClientRegistrationEnabled", "PasswordPolicy", "PKCERequired", "ImplicitFlowEnabled",
				"ResourceOwnerPasswordCredentialsEnabled"},
		},
		{
			name: "ui theme",
			path: "/api/v1/admin/settings/ui-theme",
			body: func(*testing.T) string { return `{"uiTheme":"` + uithemes.Get()[0] + `"}` },
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsUIThemePut(database, auditLogger)
			},
			owns: []string{"UITheme"},
		},
		{
			name: "email, enabled",
			path: "/api/v1/admin/settings/email",
			body: func(t *testing.T) string { return emailSettingsBody(t, true, listeningSMTPPort(t)) },
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsEmailPut(database, accountvalidation.NewEmailValidator(nil), auditLogger, testDataCipher)
			},
			owns: emailSectionColumns,
		},
		{
			name: "email, disabled",
			path: "/api/v1/admin/settings/email",
			body: func(t *testing.T) string { return emailSettingsBody(t, false, 0) },
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsEmailPut(database, accountvalidation.NewEmailValidator(nil), auditLogger, testDataCipher)
			},
			owns: emailSectionColumns,
		},
		{
			name: "sessions",
			path: "/api/v1/admin/settings/sessions",
			body: func(*testing.T) string {
				return `{"userSessionIdleTimeoutInSeconds":3000,"userSessionMaxLifetimeInSeconds":86000,"maxUserSessionsPerUser":7}`
			},
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsSessionsPut(database, auditLogger)
			},
			owns: []string{"UserSessionIdleTimeoutInSeconds", "UserSessionMaxLifetimeInSeconds", "MaxUserSessionsPerUser"},
		},
		{
			name: "tokens",
			path: "/api/v1/admin/settings/tokens",
			body: func(*testing.T) string {
				return `{"tokenExpirationInSeconds":900,"refreshTokenOfflineIdleTimeoutInSeconds":4000,` +
					`"refreshTokenOfflineMaxLifetimeInSeconds":9000,"includeOpenIDConnectClaimsInAccessToken":false,` +
					`"includeOpenIDConnectClaimsInIdToken":false}`
			},
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsTokensPut(database, auditLogger)
			},
			owns: []string{"TokenExpirationInSeconds", "RefreshTokenOfflineIdleTimeoutInSeconds",
				"RefreshTokenOfflineMaxLifetimeInSeconds", "IncludeOpenIDConnectClaimsInAccessToken",
				"IncludeOpenIDConnectClaimsInIdToken"},
		},
		{
			name: "audit logs",
			path: "/api/v1/admin/settings/audit-logs",
			body: func(*testing.T) string {
				return `{"auditLogsInConsoleEnabled":false,"auditLogsInDatabaseEnabled":false,"auditLogRetentionDays":12}`
			},
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsAuditLogsPut(database, auditLogger)
			},
			owns: []string{"AuditLogsInConsoleEnabled", "AuditLogsInDatabaseEnabled", "AuditLogRetentionDays"},
		},
	}
}

var emailSectionColumns = []string{"SMTPEnabled", "SMTPHost", "SMTPPort", "SMTPEncryption", "SMTPUsername",
	"SMTPPasswordEncrypted", "SMTPFromName", "SMTPFromEmail"}

// settingsAsTheRequestLoadedThem is the row each save's request started with.
func settingsAsTheRequestLoadedThem() record.Settings {
	before := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return record.Settings{
		Id:                                      1,
		CreatedAt:                               sql.NullTime{Time: before, Valid: true},
		UpdatedAt:                               sql.NullTime{Time: before, Valid: true},
		AppName:                                 "Before",
		Issuer:                                  "https://before.example",
		PasswordPolicy:                          record.PasswordPolicyLow,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
		UserSessionIdleTimeoutInSeconds:         600,
		UserSessionMaxLifetimeInSeconds:         3600,
		MaxUserSessionsPerUser:                  20,
		SMTPHost:                                "before.example.test",
		SMTPPort:                                25,
		SMTPUsername:                            "before",
		SMTPFromName:                            "Before",
		SMTPFromEmail:                           "before@example.test",
		SMTPEncryption:                          "none",
		AuditLogRetentionDays:                   30,
	}
}

// settingsSavedMeanwhile is the same row after saves of every section committed since the request
// loaded it: every column but the id differs from settingsAsTheRequestLoadedThem.
func settingsSavedMeanwhile() record.Settings {
	meanwhile := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	return record.Settings{
		Id:                      1,
		CreatedAt:               sql.NullTime{Time: meanwhile, Valid: true},
		UpdatedAt:               sql.NullTime{Time: meanwhile, Valid: true},
		AppName:                 "Meanwhile",
		Issuer:                  "https://meanwhile.example",
		UITheme:                 "meanwhile-theme",
		PasswordPolicy:          record.PasswordPolicyHigh,
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		TokenExpirationInSeconds:                  301,
		RefreshTokenOfflineIdleTimeoutInSeconds:   1801,
		RefreshTokenOfflineMaxLifetimeInSeconds:   7201,
		UserSessionIdleTimeoutInSeconds:           601,
		UserSessionMaxLifetimeInSeconds:           3601,
		IncludeOpenIDConnectClaimsInAccessToken:   true,
		IncludeOpenIDConnectClaimsInIdToken:       true,
		MaxUserSessionsPerUser:                    21,
		AESEncryptionKeyLegacy:                    []byte("legacy"),
		SMTPHost:                                  "meanwhile.example.test",
		SMTPPort:                                  2525,
		SMTPUsername:                              "meanwhile",
		SMTPPasswordEncrypted:                     []byte("meanwhile-ciphertext"),
		SMTPFromName:                              "Meanwhile",
		SMTPFromEmail:                             "meanwhile@example.test",
		SMTPEncryption:                            "starttls",
		SMTPEnabled:                               true,
		DynamicClientRegistrationEnabled:          true,
		PKCERequired:                              true,
		ImplicitFlowEnabled:                       true,
		ResourceOwnerPasswordCredentialsEnabled:   true,
		AuditLogsInConsoleEnabled:                 true,
		AuditLogsInDatabaseEnabled:                true,
		AuditLogRetentionDays:                     31,
		LastCleanupAt:                             sql.NullTime{Time: meanwhile, Valid: true},
	}
}

// serveSectionSave runs one section's save as an authserver:manage caller whose request loaded
// loaded.
func serveSectionSave(save settingsSectionSave, database settingsSaveDatabase, auditLogger AuditLogger,
	body string, loaded record.Settings) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, save.path, strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &loaded))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
	rr := httptest.NewRecorder()
	save.handler(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// The two rows the next test runs between differ in every column but the id, or a column the test
// says survives could be one the save wrote back unchanged.
func TestSettingsSectionSaves_TheTwoRowsDifferInEveryColumn(t *testing.T) {
	loaded, meanwhile := settingsAsTheRequestLoadedThem(), settingsSavedMeanwhile()
	lv, mv := reflect.ValueOf(loaded), reflect.ValueOf(meanwhile)
	for i := 0; i < lv.NumField(); i++ {
		name := lv.Type().Field(i).Name
		if name == "Id" {
			continue
		}
		assert.False(t, reflect.DeepEqual(lv.Field(i).Interface(), mv.Field(i).Interface()),
			"%s is the same in both rows", name)
	}
}

// Each section's save writes its own columns onto the row as stored when it runs, read under the
// row's lock inside its transaction, so a save of another section committed since its request
// loaded the settings is kept rather than written back over from that copy (#407).
func TestSettingsSectionSaves_EverySaveKeepsWhatOtherSectionsSavedMeanwhile(t *testing.T) {
	for _, save := range settingsSectionSaves() {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

			datamocks.ExpectRunInTransaction(database, settingsSaveTx)
			var steps []string
			database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).
				Run(func(context.Context, *sql.Tx, int64) { steps = append(steps, "acquire") }).Return(nil).Once()
			database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, int64(1)).
				RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
					steps = append(steps, "read")
					stored := settingsSavedMeanwhile()
					return &stored, nil
				}).Once()
			var saved record.Settings
			database.EXPECT().UpdateSettings(mock.Anything, settingsSaveTx, mock.Anything).
				Run(func(_ context.Context, _ *sql.Tx, settings *record.Settings) {
					steps = append(steps, "write")
					saved = *settings
				}).Return(nil).Once()

			rr := serveSectionSave(save, database, auditLogger, save.body(t), settingsAsTheRequestLoadedThem())

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, []string{"acquire", "read", "write"}, steps)
			owns := map[string]bool{}
			for _, column := range save.owns {
				owns[column] = true
			}
			meanwhile := settingsSavedMeanwhile()
			sv, mv := reflect.ValueOf(saved), reflect.ValueOf(meanwhile)
			for i := 0; i < sv.NumField(); i++ {
				name := sv.Type().Field(i).Name
				if owns[name] {
					continue
				}
				assert.Equal(t, mv.Field(i).Interface(), sv.Field(i).Interface(),
					"the %s save wrote %s back from the copy its request loaded", save.name, name)
			}
		})
	}
}

// A save whose transaction fails answers 500 and records nothing.
func TestSettingsSectionSaves_AFailedTransactionRecordsNothing(t *testing.T) {
	for _, save := range settingsSectionSaves() {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			datamocks.ExpectRunInTransaction(database, settingsSaveTx)
			database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).
				Return(errors.New("lock wait timeout")).Once()

			rr := serveSectionSave(save, database, auditLogger, save.body(t), settingsAsTheRequestLoadedThem())

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			database.AssertNotCalled(t, "UpdateSettings", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A kept SMTP password is the one the request's host check read, not the one the save reads under
// its lock: a save of another host and its password committed meanwhile must not have that
// password sent to this save's host (#410 decision 2).
func TestSettingsEmailPut_AKeptPasswordIsTheOneTheHostCheckRead(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	datamocks.ExpectRunInTransaction(database, settingsSaveTx)
	database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).Return(nil).Once()
	database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, int64(1)).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
			stored := settingsAsTheRequestLoadedThem()
			stored.SMTPHost = "elsewhere.example.test"
			stored.SMTPPasswordEncrypted = []byte("the-password-for-elsewhere")
			return &stored, nil
		}).Once()
	var saved record.Settings
	database.EXPECT().UpdateSettings(mock.Anything, settingsSaveTx, mock.Anything).
		Run(func(_ context.Context, _ *sql.Tx, settings *record.Settings) { saved = *settings }).Return(nil).Once()

	loaded := settingsAsTheRequestLoadedThem()
	loaded.SMTPHost = "127.0.0.1"
	loaded.SMTPPasswordEncrypted = []byte("the-password-for-this-host")
	save := settingsSectionSaves()[2]
	rr := serveSectionSave(save, database, auditLogger, save.body(t), loaded)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "127.0.0.1", saved.SMTPHost)
	assert.Equal(t, []byte("the-password-for-this-host"), saved.SMTPPasswordEncrypted)
}

// lockingSettingsStore is one settings row behind a row lock, as an engine holds it: taken by
// AcquireSettingsRow and released when the transaction that took it ends.
type lockingSettingsStore struct {
	rowLock sync.Mutex

	mu      sync.Mutex
	row     record.Settings
	holders map[*sql.Tx]bool
}

func (s *lockingSettingsStore) RunInTransaction(_ context.Context, fn func(tx *sql.Tx) error) error {
	tx := &sql.Tx{}
	err := fn(tx)
	s.mu.Lock()
	held := s.holders[tx]
	delete(s.holders, tx)
	s.mu.Unlock()
	if held {
		s.rowLock.Unlock()
	}
	return err
}

func (s *lockingSettingsStore) AcquireSettingsRow(_ context.Context, tx *sql.Tx, _ int64) error {
	s.rowLock.Lock()
	s.mu.Lock()
	s.holders[tx] = true
	s.mu.Unlock()
	return nil
}

func (s *lockingSettingsStore) GetSettingsById(_ context.Context, _ *sql.Tx, _ int64) (*record.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.row
	return &stored, nil
}

func (s *lockingSettingsStore) UpdateSettings(_ context.Context, _ *sql.Tx, settings *record.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.row = *settings
	return nil
}

// Saves of different sections whose requests all loaded the row before any of them wrote, run at
// once, each keep their change: none is written back over from a copy loaded before it. Run under
// the race tier (./run-tests.sh --type modules --race), which is what checks the saves share
// nothing but the row's lock (#407).
func TestSettingsSectionSaves_ConcurrentSavesOfDifferentSectionsAllSurvive(t *testing.T) {
	saves := settingsSectionSaves()
	concurrent := []settingsSectionSave{saves[0], saves[1], saves[4], saves[5], saves[6]}

	for round := 0; round < 10; round++ {
		store := &lockingSettingsStore{row: settingsAsTheRequestLoadedThem(), holders: map[*sql.Tx]bool{}}
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		start := make(chan struct{})
		codes := make([]int, len(concurrent))
		var wg sync.WaitGroup
		for i, save := range concurrent {
			body := save.body(t)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				codes[i] = serveSectionSave(save, store, auditLogger, body, settingsAsTheRequestLoadedThem()).Code
			}()
		}
		close(start)
		wg.Wait()

		for i, code := range codes {
			require.Equal(t, http.StatusOK, code, "round %d: the %s save", round, concurrent[i].name)
		}
		row := store.row
		assert.Equal(t, "Mine", row.AppName, "round %d: the general save was lost", round)
		assert.Equal(t, record.PasswordPolicyMedium, row.PasswordPolicy, "round %d: the general save was lost", round)
		assert.Equal(t, uithemes.Get()[0], row.UITheme, "round %d: the ui theme save was lost", round)
		assert.Equal(t, 7, row.MaxUserSessionsPerUser, "round %d: the sessions save was lost", round)
		assert.Equal(t, 3000, row.UserSessionIdleTimeoutInSeconds, "round %d: the sessions save was lost", round)
		assert.Equal(t, 900, row.TokenExpirationInSeconds, "round %d: the tokens save was lost", round)
		assert.Equal(t, 12, row.AuditLogRetentionDays, "round %d: the audit log save was lost", round)
	}
}
