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
	stored.TurnstileSecretKeyEncrypted = bytes.Clone(loaded.TurnstileSecretKeyEncrypted)
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

// settingsSectionSave is one of the eight settings writes, with a body its handler accepts and the
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
		{
			name: "turnstile",
			path: "/api/v1/admin/settings/turnstile",
			body: func(*testing.T) string {
				return `{"turnstileEnabled":true,"turnstileSiteKey":"saved-site-key","turnstileSecretKey":"saved-secret-key"}`
			},
			handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
				return HandleSettingsTurnstilePut(database, auditLogger, testDataCipher, acceptingSecretKeyChecker())
			},
			owns: []string{"TurnstileEnabled", "TurnstileSiteKey", "TurnstileSecretKeyEncrypted"},
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
		TurnstileSiteKey:                        "before-site-key",
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
		TurnstileEnabled:                          true,
		TurnstileSiteKey:                          "meanwhile-site-key",
		TurnstileSecretKeyEncrypted:               []byte("meanwhile-turnstile-ciphertext"),
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

// A kept Turnstile secret key is the one the request's site key check read, not the one the save
// reads under its lock: a save of another site key and its secret key committed meanwhile must not
// leave this save's site key paired with that widget's secret key (#642 decision 11).
func TestSettingsTurnstilePut_AKeptSecretKeyIsTheOneTheSiteKeyCheckRead(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	datamocks.ExpectRunInTransaction(database, settingsSaveTx)
	database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).Return(nil).Once()
	database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, int64(1)).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
			stored := settingsAsTheRequestLoadedThem()
			stored.TurnstileSiteKey = "another-widget-site-key"
			stored.TurnstileSecretKeyEncrypted = []byte("another-widget-secret-key")
			return &stored, nil
		}).Once()
	var saved record.Settings
	database.EXPECT().UpdateSettings(mock.Anything, settingsSaveTx, mock.Anything).
		Run(func(_ context.Context, _ *sql.Tx, settings *record.Settings) { saved = *settings }).Return(nil).Once()

	loaded := settingsAsTheRequestLoadedThem()
	loaded.TurnstileEnabled = true
	loaded.TurnstileSiteKey = "this-widget-site-key"
	loaded.TurnstileSecretKeyEncrypted = []byte("this-widget-secret-key")
	save := settingsSectionSave{
		name: "turnstile, keeping the secret key",
		path: "/api/v1/admin/settings/turnstile",
		handler: func(database settingsSaveDatabase, auditLogger AuditLogger) http.Handler {
			return HandleSettingsTurnstilePut(database, auditLogger, testDataCipher, acceptingSecretKeyChecker())
		},
	}
	rr := serveSectionSave(save, database, auditLogger,
		`{"turnstileEnabled":true,"turnstileSiteKey":"this-widget-site-key"}`, loaded)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "this-widget-site-key", saved.TurnstileSiteKey)
	assert.Equal(t, []byte("this-widget-secret-key"), saved.TurnstileSecretKeyEncrypted)
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
	concurrent := []settingsSectionSave{saves[0], saves[1], saves[4], saves[5], saves[6], saves[7]}

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
		assert.Equal(t, "saved-site-key", row.TurnstileSiteKey, "round %d: the turnstile save was lost", round)
	}
}

// settingsSectionReplaced is what each section that records the values it replaced logs of them,
// computed from the row the save wrote onto. The other sections log only their new values.
var settingsSectionReplaced = map[string]func(stored record.Settings) map[string]interface{}{
	"sessions": func(stored record.Settings) map[string]interface{} {
		return map[string]interface{}{"old": sessionsSettingsAuditValues(&stored)}
	},
	"tokens": func(stored record.Settings) map[string]interface{} {
		return map[string]interface{}{"old": map[string]interface{}{
			"token_expiration_in_seconds":                    stored.TokenExpirationInSeconds,
			"refresh_token_offline_idle_timeout_in_seconds":  stored.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refresh_token_offline_max_lifetime_in_seconds":  stored.RefreshTokenOfflineMaxLifetimeInSeconds,
			"include_open_id_connect_claims_in_access_token": stored.IncludeOpenIDConnectClaimsInAccessToken,
			"include_open_id_connect_claims_in_id_token":     stored.IncludeOpenIDConnectClaimsInIdToken,
		}}
	},
	"ui theme": func(stored record.Settings) map[string]interface{} {
		return map[string]interface{}{"old_ui_theme": stored.UITheme}
	},
	"turnstile": func(stored record.Settings) map[string]interface{} {
		return map[string]interface{}{"old": map[string]interface{}{
			"turnstile_enabled":        stored.TurnstileEnabled,
			"turnstile_site_key":       stored.TurnstileSiteKey,
			"has_turnstile_secret_key": len(stored.TurnstileSecretKeyEncrypted) > 0,
		}}
	},
}

// The values a save records as replaced are the row's as read under its lock, which is what it
// wrote over, not the copy its request loaded: a save of the same section committed meanwhile
// changed them, and recording the request's copy would name values the row no longer held (#407).
func TestSettingsSectionSaves_TheAuditRecordsTheValuesTheSaveReplaced(t *testing.T) {
	for _, save := range settingsSectionSaves() {
		replaced, records := settingsSectionReplaced[save.name]
		if !records {
			continue
		}
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			logged := recordLoggedEvents(auditLogger)
			datamocks.ExpectRunInTransaction(database, settingsSaveTx)
			database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).Return(nil).Once()
			database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, int64(1)).
				RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
					stored := settingsSavedMeanwhile()
					return &stored, nil
				}).Once()
			database.EXPECT().UpdateSettings(mock.Anything, settingsSaveTx, mock.Anything).Return(nil).Once()

			rr := serveSectionSave(save, database, auditLogger, save.body(t), settingsAsTheRequestLoadedThem())

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.Len(t, *logged, 1)
			details := (*logged)[0].details
			for key, want := range replaced(settingsSavedMeanwhile()) {
				assert.Equal(t, want, details[key], "the %s save recorded %s from the copy its request loaded", save.name, key)
			}
		})
	}
}

// The engine reruns a transaction's body when it aborts it as a deadlock victim, so a save's apply
// runs once per attempt, each on that attempt's own read. What the save writes and what it records
// is the committed attempt's: its write carries the other sections as that attempt read them, and
// the values it records as replaced are that attempt's, not the aborted one's (#407).
func TestSettingsSectionSaves_ARerunBodyWritesAndRecordsTheCommittedAttempt(t *testing.T) {
	for _, save := range settingsSectionSaves() {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			logged := recordLoggedEvents(auditLogger)
			datamocks.ExpectRunInTransactionRerun(database, settingsSaveTx)
			database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, int64(1)).Return(nil).Times(2)
			// The aborted attempt reads the row as the request loaded it; the committed one reads it
			// after saves of every section committed between the two.
			reads := 0
			database.EXPECT().GetSettingsById(mock.Anything, settingsSaveTx, int64(1)).
				RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
					reads++
					stored := settingsAsTheRequestLoadedThem()
					if reads > 1 {
						stored = settingsSavedMeanwhile()
					}
					return &stored, nil
				}).Times(2)
			var writes []record.Settings
			database.EXPECT().UpdateSettings(mock.Anything, settingsSaveTx, mock.Anything).
				Run(func(_ context.Context, _ *sql.Tx, settings *record.Settings) { writes = append(writes, *settings) }).
				Return(nil).Times(2)

			rr := serveSectionSave(save, database, auditLogger, save.body(t), settingsAsTheRequestLoadedThem())

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.Len(t, writes, 2)
			owns := map[string]bool{}
			for _, column := range save.owns {
				owns[column] = true
			}
			meanwhile := settingsSavedMeanwhile()
			cv, mv := reflect.ValueOf(writes[1]), reflect.ValueOf(meanwhile)
			for i := 0; i < cv.NumField(); i++ {
				name := cv.Type().Field(i).Name
				if owns[name] {
					continue
				}
				assert.Equal(t, mv.Field(i).Interface(), cv.Field(i).Interface(),
					"the committed attempt of the %s save wrote %s from the aborted attempt's read", save.name, name)
			}
			require.Len(t, *logged, 1, "one record, for the committed attempt")
			if replaced, records := settingsSectionReplaced[save.name]; records {
				details := (*logged)[0].details
				for key, want := range replaced(meanwhile) {
					assert.Equal(t, want, details[key], "the %s save recorded %s from the aborted attempt", save.name, key)
				}
			}
		})
	}
}

// settingsSaveStore is a settingsSaveDatabase whose read answers row, nil for a row that is not
// there, and which counts the writes it is asked for.
type settingsSaveStore struct {
	row    *record.Settings
	writes int
}

func (s *settingsSaveStore) RunInTransaction(_ context.Context, fn func(tx *sql.Tx) error) error {
	return fn(settingsSaveTx)
}

func (s *settingsSaveStore) AcquireSettingsRow(context.Context, *sql.Tx, int64) error { return nil }

func (s *settingsSaveStore) GetSettingsById(context.Context, *sql.Tx, int64) (*record.Settings, error) {
	if s.row == nil {
		return nil, nil
	}
	stored := *s.row
	return &stored, nil
}

func (s *settingsSaveStore) UpdateSettings(context.Context, *sql.Tx, *record.Settings) error {
	s.writes++
	return nil
}

// A settings row that is gone by the time the save reads it under its lock is an error, and
// nothing is applied or written: the lock holds no row, and writing would update none.
func TestSaveSettingsSection_ARowThatIsGoneWritesNothing(t *testing.T) {
	store := &settingsSaveStore{}
	applied := false

	saved, err := saveSettingsSection(context.Background(), store, 1, func(*record.Settings) { applied = true })

	require.Error(t, err)
	assert.Nil(t, saved)
	assert.False(t, applied, "the section was applied to a row that is not there")
	assert.Zero(t, store.writes, "a save wrote a row that is not there")
}
