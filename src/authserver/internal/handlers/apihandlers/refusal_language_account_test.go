package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// The refusals of the account API: email, email verification, password, two-factor authentication
// and the logout request, served once with no language and once in pt-BR through
// assertRefusalLanguages (#559 decisions 1 and 2). The body that does not parse and the missing or
// malformed session and consent ids are an integrator's, and stay English. The phone save's own
// country check is a second line behind ValidatePhone, which refuses an unknown country first, so no
// request reaches it.

const accountRefusalSubject = "account-refusal-subject"

// accountRefusalRequest is a request to one account endpoint from accountRefusalSubject, under the
// settings the handler reads.
func accountRefusalRequest(t *testing.T, method, target string, body any, settings *record.Settings, acceptLanguage string) *http.Request {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		require.NoError(t, err)
	}
	r := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
	r = setTokenContextWithClaims(r, map[string]interface{}{"sub": accountRefusalSubject, "sid": logoutSid})
	return inRequestLanguage(r, acceptLanguage)
}

// accountRefusalUser is the caller's row, holding password.
func accountRefusalUser(t *testing.T, password string) *record.User {
	t.Helper()
	hash, err := passwordhash.Hash(password)
	require.NoError(t, err)
	return &record.User{Id: 42, Subject: accountRefusalSubject, Enabled: true, Email: "old@example.com", PasswordHash: hash}
}

// callerIs answers the caller's row, as many times as the handler reads it.
func callerIs(user *record.User) func(database *datamocks.Database) {
	return func(database *datamocks.Database) {
		database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), accountRefusalSubject).Return(user, nil)
	}
}

// serveAccount answers one request to the handler built over a database expecting what expect
// registers.
func serveAccount(method, target string, body any, settings *record.Settings, expect func(database *datamocks.Database),
	handler func(t *testing.T, database *datamocks.Database) http.Handler,
) func(*testing.T, string) *httptest.ResponseRecorder {
	return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
		database := datamocks.NewDatabase(t)
		if expect != nil {
			expect(database)
		}
		rr := httptest.NewRecorder()
		handler(t, database).ServeHTTP(rr, accountRefusalRequest(t, method, target, body, settings, acceptLanguage))
		return rr
	}
}

// TestAccountEmailAndPasswordRefusals_AreInTheRequestsLanguage covers the email change, the password
// change and the email verification's send and check.
func TestAccountEmailAndPasswordRefusals_AreInTheRequestsLanguage(t *testing.T) {
	const password = "C0rrect!Pass"
	smtpOn := &record.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}
	smtpOff := &record.Settings{}

	email := func(body api.UpdateAccountEmailRequest, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveAccount(http.MethodPut, "/api/v1/account/email", body, smtpOn, expect,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleAccountEmailPut(handlersmocks.NewPageRenderer(t), database, accountvalidation.NewEmailValidator(database),
					accounthandlersmocks.NewEmailSender(t), handlersmocks.NewAuditLogger(t), unlimitedCredentials{}, &heldJobs{})
			})
	}
	passwordChange := func(current, next string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		body := api.UpdateAccountPasswordRequest{CurrentPassword: current, NewPassword: next}
		return serveAccount(http.MethodPut, "/api/v1/account/password", body, &record.Settings{PasswordPolicy: record.PasswordPolicyLow}, expect,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleAccountPasswordPut(database, accountvalidation.NewPasswordValidator(), handlersmocks.NewAuditLogger(t), unlimitedCredentials{})
			})
	}
	send := func(settings *record.Settings, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveAccount(http.MethodPost, "/api/v1/account/email/verification/send", nil, settings, expect,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleAccountEmailVerificationSendPost(handlersmocks.NewPageRenderer(t), database, accounthandlersmocks.NewEmailSender(t),
					handlersmocks.NewAuditLogger(t), testDataCipher, testAdminConsoleBaseURL)
			})
	}
	verify := func(settings *record.Settings, code string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveAccount(http.MethodPost, "/api/v1/account/email/verification", api.VerifyAccountEmailRequest{VerificationCode: code}, settings, expect,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				auditLogger := handlersmocks.NewAuditLogger(t)
				auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
				return HandleAccountEmailVerificationPost(database, auditLogger, unlimitedCredentials{}, testDataCipher)
			})
	}
	pendingCode := func(t *testing.T) *record.User {
		user := pendingCodeUser(t)
		user.Subject = accountRefusalSubject
		return user
	}

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "an email change with no current password",
			serve:      email(api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: " "}, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Current password is required.",
			portuguese: "A senha atual é obrigatória.",
		},
		{
			name:       "an email change with a wrong current password",
			serve:      email(api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: "wrong"}, callerIs(accountRefusalUser(t, password))),
			status:     http.StatusBadRequest,
			code:       "AUTHENTICATION_FAILED",
			english:    "Authentication failed. Check your current password and try again.",
			portuguese: "Falha na autenticação. Verifique sua senha atual e tente novamente.",
		},
		{
			name: "an email change losing to a concurrent change",
			serve: email(api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: password},
				func(database *datamocks.Database) {
					callerIs(accountRefusalUser(t, password))(database)
					database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
					database.On("TrySetUserEmail", mock.Anything, (*sql.Tx)(nil), int64(42), "old@example.com", false, "new@example.com").
						Return(false, nil).Once()
				}),
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The account was changed by another request after it was loaded. Nothing was saved: reload it and make the change again.",
			portuguese: "A conta foi alterada por outra requisição depois de ser carregada. Nada foi salvo: recarregue-a e faça a alteração novamente.",
		},
		{
			name:       "a password change with no current password",
			serve:      passwordChange("", "N3wP4ss!word", nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Current password is required.",
			portuguese: "A senha atual é obrigatória.",
		},
		{
			name:       "a password change with no new password",
			serve:      passwordChange(password, " ", nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "New password is required.",
			portuguese: "A nova senha é obrigatória.",
		},
		{
			name:       "a password change with a wrong current password",
			serve:      passwordChange("wrong", "N3wP4ss!word", callerIs(accountRefusalUser(t, password))),
			status:     http.StatusBadRequest,
			code:       "AUTHENTICATION_FAILED",
			english:    "Authentication failed. Check your current password and try again.",
			portuguese: "Falha na autenticação. Verifique sua senha atual e tente novamente.",
		},
		{
			name:       "a verification code sent with SMTP off",
			serve:      send(smtpOff, nil),
			status:     http.StatusBadRequest,
			code:       "SMTP_NOT_ENABLED",
			english:    "SMTP is not enabled",
			portuguese: "O SMTP não está habilitado",
		},
		{
			name: "a verification code send losing to an email change",
			serve: send(smtpOn, func(database *datamocks.Database) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), accountRefusalSubject).
					Return(&record.User{Id: 7, Subject: accountRefusalSubject, Email: "anyone@example.com"}, nil).Once()
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), accountRefusalSubject).
					Return(&record.User{Id: 7, Subject: accountRefusalSubject, Email: "elsewhere@example.com"}, nil).Once()
				database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "anyone@example.com",
					mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()
			}),
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The account was changed by another request while the code was being sent. Nothing was sent: try again.",
			portuguese: "A conta foi alterada por outra requisição enquanto o código era enviado. Nada foi enviado: tente novamente.",
		},
		{
			name:       "a verification code checked with SMTP off",
			serve:      verify(smtpOff, verificationCode, nil),
			status:     http.StatusBadRequest,
			code:       "SMTP_NOT_ENABLED",
			english:    "SMTP is not enabled",
			portuguese: "O SMTP não está habilitado",
		},
		{
			name: "a wrong verification code",
			serve: verify(smtpOn, "WRONG123", func(database *datamocks.Database) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), accountRefusalSubject).Return(pendingCode(t), nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "INVALID_OR_EXPIRED_VERIFICATION_CODE",
			english:    "Invalid or expired verification code",
			portuguese: "Código de verificação inválido ou expirado",
		},
		{
			name: "a right verification code replaced before it was spent",
			serve: verify(smtpOn, verificationCode, func(database *datamocks.Database) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), accountRefusalSubject).Return(pendingCode(t), nil).Twice()
				database.On("TryVerifyUserEmail", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com", mock.Anything).
					Return(false, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "INVALID_OR_EXPIRED_VERIFICATION_CODE",
			english:    "Invalid or expired verification code",
			portuguese: "Código de verificação inválido ou expirado",
		},
	})
}

// TestAccountOTPRefusals_AreInTheRequestsLanguage covers the enrolment, enabling and disabling the
// authenticator, and the answers of an enable or a disable that lost to a concurrent change.
func TestAccountOTPRefusals_AreInTheRequestsLanguage(t *testing.T) {
	const password = "P4ss!word"
	settings := &record.Settings{AppName: "Goiabada"}

	enrollment := func(user *record.User) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveAccount(http.MethodGet, "/api/v1/account/otp/enrollment", nil, settings, callerIs(user),
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleAccountOTPEnrollmentGet(database, handlersmocks.NewOtpSecretGenerator(t), testDataCipher)
			})
	}
	put := func(body map[string]interface{}, user func(t *testing.T) *record.User) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			var expect func(database *datamocks.Database)
			if user != nil {
				expect = callerIs(user(t))
			}
			return serveAccount(http.MethodPut, "/api/v1/account/otp", body, settings, expect,
				func(t *testing.T, database *datamocks.Database) http.Handler {
					return HandleAccountOTPPut(database, handlersmocks.NewAuditLogger(t), unlimitedCredentials{}, testDataCipher)
				})(t, acceptLanguage)
		}
	}
	enrolling := func(t *testing.T) *record.User {
		user := otpTestUser(t, password)
		user.Subject = accountRefusalSubject
		return user
	}
	enrolled := func(t *testing.T) *record.User {
		user := accountRefusalUser(t, password)
		user.OTPEnabled = true
		return user
	}
	noEnrollment := func(t *testing.T) *record.User { return accountRefusalUser(t, password) }
	lostChange := func(current *record.User, wantEnabled bool) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(current, nil).Once()
			rr := httptest.NewRecorder()
			writeLostOTPChange(rr, inRequestLanguage(httptest.NewRequest(http.MethodPut, "/api/v1/account/otp", nil), acceptLanguage),
				database, 42, wantEnabled)
			return rr
		}
	}

	const alreadyEnabledEnglish = "OTP is already enabled"
	const alreadyEnabledPortuguese = "O OTP já está habilitado"
	const notEnabledEnglish = "User does not have OTP enabled"
	const notEnabledPortuguese = "O usuário não tem o OTP habilitado"
	const invalidCodeEnglish = "Invalid OTP code."
	const invalidCodePortuguese = "Código OTP inválido."

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "an enrolment with OTP already enabled",
			serve:      enrollment(enrolled(t)),
			status:     http.StatusBadRequest,
			code:       "OTP_ALREADY_ENABLED",
			english:    alreadyEnabledEnglish,
			portuguese: alreadyEnabledPortuguese,
		},
		{
			name:    "an enable naming a secretKey",
			serve:   put(map[string]interface{}{"enabled": true, "password": password, "secretKey": otpTestSecret}, nil),
			status:  http.StatusBadRequest,
			code:    "SECRET_KEY_NOT_ACCEPTED",
			english: "This endpoint no longer accepts a secretKey. Start an enrollment with GET /api/v1/account/otp/enrollment and submit only the code from your authenticator app.",
			portuguese: "Este endpoint não aceita mais um secretKey. Inicie um cadastro com GET /api/v1/account/otp/enrollment " +
				"e envie apenas o código do seu aplicativo autenticador.",
		},
		{
			name:       "a change with no password",
			serve:      put(map[string]interface{}{"enabled": false, "password": " "}, noEnrollment),
			status:     http.StatusBadRequest,
			code:       "AUTHENTICATION_FAILED",
			english:    "Authentication failed. Check your password and try again.",
			portuguese: "Falha na autenticação. Verifique sua senha e tente novamente.",
		},
		{
			name:       "a change with a wrong password",
			serve:      put(map[string]interface{}{"enabled": false, "password": "wrong"}, noEnrollment),
			status:     http.StatusBadRequest,
			code:       "AUTHENTICATION_FAILED",
			english:    "Authentication failed. Check your password and try again.",
			portuguese: "Falha na autenticação. Verifique sua senha e tente novamente.",
		},
		{
			name:       "an enable with OTP already enabled",
			serve:      put(map[string]interface{}{"enabled": true, "password": password, "otpCode": "123456"}, enrolled),
			status:     http.StatusBadRequest,
			code:       "OTP_ALREADY_ENABLED",
			english:    alreadyEnabledEnglish,
			portuguese: alreadyEnabledPortuguese,
		},
		{
			name:       "an enable with no code",
			serve:      put(map[string]interface{}{"enabled": true, "password": password, "otpCode": " "}, enrolling),
			status:     http.StatusBadRequest,
			code:       "OTP_CODE_REQUIRED",
			english:    "OTP code is required to enable.",
			portuguese: "O código OTP é obrigatório para habilitar.",
		},
		{
			name:       "an enable with a code of five digits",
			serve:      put(map[string]interface{}{"enabled": true, "password": password, "otpCode": "12345"}, enrolling),
			status:     http.StatusBadRequest,
			code:       "INVALID_OTP_CODE",
			english:    invalidCodeEnglish,
			portuguese: invalidCodePortuguese,
		},
		{
			name:       "an enable with a code that is not digits",
			serve:      put(map[string]interface{}{"enabled": true, "password": password, "otpCode": "12345a"}, enrolling),
			status:     http.StatusBadRequest,
			code:       "INVALID_OTP_CODE",
			english:    invalidCodeEnglish,
			portuguese: invalidCodePortuguese,
		},
		{
			name:    "an enable with no enrolment pending",
			serve:   put(map[string]interface{}{"enabled": true, "password": password, "otpCode": "123456"}, noEnrollment),
			status:  http.StatusBadRequest,
			code:    "OTP_ENROLLMENT_NOT_PENDING",
			english: "No OTP enrollment is pending, or the one you started has expired. Request a new one with GET /api/v1/account/otp/enrollment and try again.",
			portuguese: "Nenhum cadastro de OTP está pendente, ou o que você iniciou expirou. Solicite um novo com " +
				"GET /api/v1/account/otp/enrollment e tente novamente.",
		},
		{
			name: "an enable with a wrong code",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				return put(map[string]interface{}{"enabled": true, "password": password, "otpCode": wrongButWellFormedCode(t)}, enrolling)(t, acceptLanguage)
			},
			status:     http.StatusBadRequest,
			code:       "INVALID_OTP_CODE",
			english:    "That code isn't right. Codes change every 30 seconds, so enter the one your app shows now.",
			portuguese: "Esse código não está correto. Os códigos mudam a cada 30 segundos, então digite o que o aplicativo mostra agora.",
		},
		{
			name:       "a disable with OTP not enabled",
			serve:      put(map[string]interface{}{"enabled": false, "password": password}, noEnrollment),
			status:     http.StatusBadRequest,
			code:       "OTP_NOT_ENABLED",
			english:    notEnabledEnglish,
			portuguese: notEnabledPortuguese,
		},
		{
			name:       "an enable that lost to another enable",
			serve:      lostChange(&record.User{Id: 42, OTPEnabled: true}, true),
			status:     http.StatusBadRequest,
			code:       "OTP_ALREADY_ENABLED",
			english:    alreadyEnabledEnglish,
			portuguese: alreadyEnabledPortuguese,
		},
		{
			name:       "a disable that lost to another disable",
			serve:      lostChange(&record.User{Id: 42, OTPEnabled: false}, false),
			status:     http.StatusBadRequest,
			code:       "OTP_NOT_ENABLED",
			english:    notEnabledEnglish,
			portuguese: notEnabledPortuguese,
		},
		{
			name:       "a change that lost to a change it cannot account for",
			serve:      lostChange(&record.User{Id: 42, OTPEnabled: true}, false),
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The account was changed by another request after it was loaded. Nothing was saved: reload it and make the change again.",
			portuguese: "A conta foi alterada por outra requisição depois de ser carregada. Nada foi salvo: recarregue-a e faça a alteração novamente.",
		},
	})
}

// TestAccountLogoutRefusals_AreInTheRequestsLanguage covers the logout request's parameters, which
// decision 1 translates although only a hand-made request sends them wrong.
func TestAccountLogoutRefusals_AreInTheRequestsLanguage(t *testing.T) {
	settings := &record.Settings{Issuer: "https://auth.example.com"}
	logout := func(postLogout, clientIdentifier string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		body := api.AccountLogoutRequest{PostLogoutRedirectUri: postLogout, ClientIdentifier: clientIdentifier}
		return serveAccount(http.MethodPost, "/api/v1/account/logout-request", body, settings, expect,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL)
			})
	}

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "no post-logout redirect URI",
			serve:      logout("", logoutClientIdent, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "postLogoutRedirectUri is required",
			portuguese: "postLogoutRedirectUri é obrigatório",
		},
		{
			name: "a client identifier naming no client",
			serve: logout(logoutPostLogoutUri, logoutClientIdent, func(database *datamocks.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), logoutClientIdent).Return(nil, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Invalid client identifier",
			portuguese: "Identificador de cliente inválido",
		},
		{
			name: "a redirect URI no client holds",
			serve: logout(logoutPostLogoutUri, "", func(database *datamocks.Database) {
				database.On("GetAllClients", mock.Anything, (*sql.Tx)(nil)).Return([]record.Client{}, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier.",
			portuguese: "Não foi possível identificar o cliente a partir do postLogoutRedirectUri; informe o clientIdentifier.",
		},
		{
			name: "a redirect URI the client does not hold",
			serve: logout(logoutPostLogoutUri, logoutClientIdent, func(database *datamocks.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), logoutClientIdent).
					Return(&record.Client{Id: 7, ClientIdentifier: logoutClientIdent}, nil).Once()
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "postLogoutRedirectUri is not registered for the client",
			portuguese: "O postLogoutRedirectUri não está registrado para o cliente",
		},
	})
}
