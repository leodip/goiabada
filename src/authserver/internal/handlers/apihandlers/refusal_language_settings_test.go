package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
)

// The refusals of the settings endpoints: general, sessions, tokens, email, audit logs, signing keys
// and the UI theme, served once with no language and once in pt-BR through assertRefusalLanguages
// (#559 decisions 1 and 2). The SMTP connection and send failures are whole sentences, one per
// cause, never an opening and a cause joined at run time. The body that does not parse and the
// malformed key id are an integrator's, and stay English. Every other refusal answers its catalog
// key as its error_code, which the console reads the field off (#617).

// settingsRefusal answers one request to the handler build makes over a database expecting what
// expect registers, as an authserver:manage caller, under settings.
func settingsRefusal(method, target string, body any, settings *record.Settings, expect func(database *datamocks.Database),
	build func(t *testing.T, database *datamocks.Database) http.Handler,
) func(*testing.T, string) *httptest.ResponseRecorder {
	return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			require.NoError(t, err)
		}
		database := datamocks.NewDatabase(t)
		if expect != nil {
			expect(database)
		}
		r := httptest.NewRequest(method, target, strings.NewReader(string(encoded)))
		r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
		r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
		rr := httptest.NewRecorder()
		build(t, database).ServeHTTP(rr, inRequestLanguage(r, acceptLanguage))
		return rr
	}
}

// TestSettingsGeneralSessionsTokensRefusals_AreInTheRequestsLanguage covers the general, sessions,
// tokens, audit log and UI theme saves.
func TestSettingsGeneralSessionsTokensRefusals_AreInTheRequestsLanguage(t *testing.T) {
	general := func(body map[string]any) func(*testing.T, string) *httptest.ResponseRecorder {
		full := map[string]any{"appName": "Goiabada", "issuer": "https://auth.example.com", "passwordPolicy": "low"}
		for key, value := range body {
			full[key] = value
		}
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/general", full, &record.Settings{}, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsGeneralPut(database, handlersmocks.NewAuditLogger(t), "http://localhost:9090")
			})
	}
	sessions := func(idle, lifetime int) func(*testing.T, string) *httptest.ResponseRecorder {
		body := map[string]any{"userSessionIdleTimeoutInSeconds": idle, "userSessionMaxLifetimeInSeconds": lifetime}
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/sessions", body, &record.Settings{}, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsSessionsPut(database, handlersmocks.NewAuditLogger(t))
			})
	}
	// sessionCap sends valid lifetimes and the cap given, which a nil leaves out.
	sessionCap := func(maxSessions any) func(*testing.T, string) *httptest.ResponseRecorder {
		body := map[string]any{"userSessionIdleTimeoutInSeconds": 100, "userSessionMaxLifetimeInSeconds": 200}
		if maxSessions != nil {
			body["maxUserSessionsPerUser"] = maxSessions
		}
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/sessions", body, &record.Settings{}, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsSessionsPut(database, handlersmocks.NewAuditLogger(t))
			})
	}
	tokens := func(expiration, idle, lifetime int) func(*testing.T, string) *httptest.ResponseRecorder {
		body := map[string]any{
			"tokenExpirationInSeconds":                expiration,
			"refreshTokenOfflineIdleTimeoutInSeconds": idle,
			"refreshTokenOfflineMaxLifetimeInSeconds": lifetime,
		}
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/tokens", body, &record.Settings{}, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsTokensPut(database, handlersmocks.NewAuditLogger(t))
			})
	}
	auditLogs := func(days int) func(*testing.T, string) *httptest.ResponseRecorder {
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/audit-logs", map[string]any{"auditLogRetentionDays": days}, &record.Settings{}, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsAuditLogsPut(database, handlersmocks.NewAuditLogger(t))
			})
	}
	const tooLarge = 160000001

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "an app name past the bound",
			serve:      general(map[string]any{"appName": strings.Repeat("a", 31)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_general.app_name_too_long",
			english:    "App name is too long. The maximum length is 30 characters.",
			portuguese: "O nome do aplicativo é longo demais. O tamanho máximo é de 30 caracteres.",
		},
		{
			name:       "an issuer that is neither an https URL nor the base URL",
			serve:      general(map[string]any{"issuer": "goiabada"}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_general.issuer_uri_invalid",
			english:    "Invalid issuer. Enter an https URL with no query, fragment or user info, or the auth server's base URL.",
			portuguese: "Issuer inválido. Informe uma URL https sem query, fragmento ou informações de usuário, ou a URL base do servidor de autenticação.",
		},
		{
			name:       "an issuer past the bound",
			serve:      general(map[string]any{"issuer": "https://auth.example.com/" + strings.Repeat("a", 36)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_general.issuer_too_long",
			english:    "Issuer is too long. The maximum length is 60 characters.",
			portuguese: "O issuer é longo demais. O tamanho máximo é de 60 caracteres.",
		},
		{
			name:       "an unknown password policy",
			serve:      general(map[string]any{"passwordPolicy": "extreme"}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_general.password_policy_invalid",
			english:    "Invalid password policy",
			portuguese: "Política de senhas inválida",
		},
		{
			name:       "a session idle timeout of zero",
			serve:      sessions(0, 100),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.idle_timeout_not_positive",
			english:    "The idle timeout must be greater than zero.",
			portuguese: "O tempo limite de inatividade precisa ser maior que zero.",
		},
		{
			name:       "a session max lifetime of zero",
			serve:      sessions(100, 0),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.max_lifetime_not_positive",
			english:    "The maximum lifetime must be greater than zero.",
			portuguese: "A duração máxima precisa ser maior que zero.",
		},
		{
			name:       "a session idle timeout past the bound",
			serve:      sessions(tooLarge, tooLarge),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.idle_timeout_too_large",
			english:    "The idle timeout cannot be more than 160000000 seconds.",
			portuguese: "O tempo limite de inatividade não pode passar de 160000000 segundos.",
		},
		{
			name:       "a session max lifetime past the bound",
			serve:      sessions(100, tooLarge),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.max_lifetime_too_large",
			english:    "The maximum lifetime cannot be more than 160000000 seconds.",
			portuguese: "A duração máxima não pode passar de 160000000 segundos.",
		},
		{
			name:       "a session idle timeout above its max lifetime",
			serve:      sessions(200, 100),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.idle_timeout_above_max_lifetime",
			english:    "The idle timeout cannot be longer than the maximum lifetime.",
			portuguese: "O tempo limite de inatividade não pode ser maior que a duração máxima.",
		},
		{
			name:       "no session cap",
			serve:      sessionCap(nil),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.max_sessions_per_user_required",
			english:    "Enter the maximum sessions per user.",
			portuguese: "Informe o máximo de sessões por usuário.",
		},
		{
			name:       "a session cap past the bound",
			serve:      sessionCap(1001),
			status:     http.StatusBadRequest,
			code:       "handler.settings_sessions.max_sessions_per_user_out_of_range",
			english:    "The maximum sessions per user must be between 0 and 1000.",
			portuguese: "O máximo de sessões por usuário precisa estar entre 0 e 1000.",
		},
		{
			name:       "a token expiration of zero",
			serve:      tokens(0, 100, 200),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.token_expiration_not_positive",
			english:    "Token expiration in seconds must be greater than zero.",
			portuguese: "A expiração do token em segundos precisa ser maior que zero.",
		},
		{
			name:       "a token expiration past the bound",
			serve:      tokens(tooLarge, 100, 200),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.token_expiration_too_large",
			english:    "Token expiration in seconds cannot be greater than 160000000.",
			portuguese: "A expiração do token em segundos não pode ser maior que 160000000.",
		},
		{
			name:       "an offline idle timeout of zero",
			serve:      tokens(300, 0, 200),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.offline_idle_timeout_not_positive",
			english:    "Refresh token offline - idle timeout in seconds must be greater than zero.",
			portuguese: "O refresh token offline - timeout por inatividade em segundos precisa ser maior que zero.",
		},
		{
			name:       "an offline idle timeout past the bound",
			serve:      tokens(300, tooLarge, 200),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.offline_idle_timeout_too_large",
			english:    "Refresh token offline - idle timeout in seconds cannot be greater than 160000000.",
			portuguese: "O refresh token offline - timeout por inatividade em segundos não pode ser maior que 160000000.",
		},
		{
			name:       "an offline max lifetime of zero",
			serve:      tokens(300, 100, 0),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.offline_max_lifetime_not_positive",
			english:    "Refresh token offline - max lifetime in seconds must be greater than zero.",
			portuguese: "O refresh token offline - tempo máximo de vida em segundos precisa ser maior que zero.",
		},
		{
			name:       "an offline max lifetime past the bound",
			serve:      tokens(300, 100, tooLarge),
			status:     http.StatusBadRequest,
			code:       "handler.settings_tokens.offline_max_lifetime_too_large",
			english:    "Refresh token offline - max lifetime in seconds cannot be greater than 160000000.",
			portuguese: "O refresh token offline - tempo máximo de vida em segundos não pode ser maior que 160000000.",
		},
		{
			name:       "an offline idle timeout above its max lifetime",
			serve:      tokens(300, 200, 100),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.offline_idle_timeout_above_max_lifetime",
			english:    "The offline idle timeout can't be longer than the offline maximum lifetime.",
			portuguese: "O tempo ocioso offline não pode ser maior que a duração máxima offline.",
		},
		{
			name:       "a negative audit log retention",
			serve:      auditLogs(-1),
			status:     http.StatusBadRequest,
			code:       "handler.settings_audit_logs.retention_days_negative",
			english:    "Audit log retention days cannot be negative. Use 0 for infinite retention.",
			portuguese: "Os dias de retenção de logs de auditoria não podem ser negativos. Use 0 para retenção indefinida.",
		},
		{
			name:       "an audit log retention past ten years",
			serve:      auditLogs(3651),
			status:     http.StatusBadRequest,
			code:       "handler.settings_audit_logs.retention_days_too_large",
			english:    "Audit log retention days cannot exceed 3650 days (10 years).",
			portuguese: "Os dias de retenção de logs de auditoria não podem passar de 3650 dias (10 anos).",
		},
		{
			name: "an unknown UI theme",
			serve: settingsRefusal(http.MethodPut, "/api/v1/admin/settings/ui-theme", map[string]any{"uiTheme": "no-such-theme"}, &record.Settings{}, nil,
				func(t *testing.T, database *datamocks.Database) http.Handler {
					return HandleSettingsUIThemePut(database, handlersmocks.NewAuditLogger(t))
				}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_ui_theme.theme_invalid",
			english:    "Invalid theme.",
			portuguese: "Tema inválido.",
		},
	})
}

// TestSettingsKeysRefusals_AreInTheRequestsLanguage covers the signing key rotation and revocation.
func TestSettingsKeysRefusals_AreInTheRequestsLanguage(t *testing.T) {
	revoke := func(stored *record.KeyPair) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetKeyPairById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(stored, nil).Once()
			r := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/settings/keys/5", nil)
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("id", "5")
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeContext))
			r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
			rr := httptest.NewRecorder()
			HandleSettingsKeyDelete(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, inRequestLanguage(r, acceptLanguage))
			return rr
		}
	}
	current := signingKey(5, record.KeyStateCurrent)

	assertRefusalLanguages(t, []refusalCase{
		{
			name: "a rotation losing to another",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				database := datamocks.NewDatabase(t)
				stubRotateRead(database, []record.KeyPair{signingKey(2, record.KeyStateCurrent), signingKey(3, record.KeyStateNext)})
				database.On("UpdateKeyPairState", mock.Anything, rotateTx, int64(2),
					record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).Return(false, nil).Once()
				rr := httptest.NewRecorder()
				HandleSettingsKeysRotatePost(database, handlersmocks.NewAuditLogger(t), testDataCipher).
					ServeHTTP(rr, inRequestLanguage(rotateRequest(), acceptLanguage))
				return rr
			},
			status:     http.StatusConflict,
			code:       "ROTATION_IN_PROGRESS",
			english:    "Another key rotation is in progress",
			portuguese: "Outra rotação de chave está em andamento",
		},
		{
			name:       "a key another administrator revoked",
			serve:      revoke(nil),
			status:     http.StatusBadRequest,
			code:       "handler.settings_keys.key_not_found",
			english:    "Key not found",
			portuguese: "Chave não encontrada",
		},
		{
			name:       "a key that is not the previous one",
			serve:      revoke(&current),
			status:     http.StatusBadRequest,
			code:       "handler.settings_keys.only_previous_revocable",
			english:    "Only a previous key can be revoked",
			portuguese: "Apenas uma chave anterior pode ser revogada",
		},
	})
}

// TestSettingsEmailRefusals_AreInTheRequestsLanguage covers the email save, its connectivity dial,
// and the test send's own refusals.
func TestSettingsEmailRefusals_AreInTheRequestsLanguage(t *testing.T) {
	save := func(settings *record.Settings, body map[string]any) func(*testing.T, string) *httptest.ResponseRecorder {
		full := map[string]any{
			"smtpEnabled":    true,
			"smtpHost":       "127.0.0.1",
			"smtpPort":       587,
			"smtpEncryption": "none",
			"smtpUsername":   "relay-user",
			"smtpFromName":   "Acme",
			"smtpFromEmail":  "noreply@example.com",
		}
		for key, value := range body {
			full[key] = value
		}
		return settingsRefusal(http.MethodPut, "/api/v1/admin/settings/email", full, settings, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsEmailPut(database, accountvalidation.NewEmailValidator(nil), handlersmocks.NewAuditLogger(t), testDataCipher)
			})
	}
	unchanged := emailSaveSettings(t, "127.0.0.1", false)
	sendTest := func(settings *record.Settings, to string) func(*testing.T, string) *httptest.ResponseRecorder {
		return settingsRefusal(http.MethodPost, "/api/v1/admin/settings/email/send-test", map[string]any{"to": to}, settings, nil,
			func(t *testing.T, database *datamocks.Database) http.Handler {
				return HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), accounthandlersmocks.NewEmailSender(t), handlersmocks.NewAuditLogger(t))
			})
	}

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "no SMTP host",
			serve:      save(unchanged, map[string]any{"smtpHost": " "}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_host_required",
			english:    "SMTP host is required.",
			portuguese: "O host SMTP é obrigatório.",
		},
		{
			name:       "no SMTP port",
			serve:      save(unchanged, map[string]any{"smtpPort": 0}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_port_required",
			english:    "SMTP port is required.",
			portuguese: "A porta SMTP é obrigatória.",
		},
		{
			name:       "no SMTP from email",
			serve:      save(unchanged, map[string]any{"smtpFromEmail": " "}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_from_email_required",
			english:    "SMTP from email is required.",
			portuguese: "O e-mail do remetente SMTP é obrigatório.",
		},
		{
			name:       "an SMTP host past the bound",
			serve:      save(unchanged, map[string]any{"smtpHost": strings.Repeat("h", 121)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_host_too_long",
			english:    "SMTP host must be less than 120 characters.",
			portuguese: "O host SMTP deve ter menos de 120 caracteres.",
		},
		{
			name:       "an SMTP port out of range",
			serve:      save(unchanged, map[string]any{"smtpPort": 65536}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_port_out_of_range",
			english:    "SMTP port must be between 1 and 65535.",
			portuguese: "A porta SMTP deve estar entre 1 e 65535.",
		},
		{
			name:       "an unknown SMTP encryption",
			serve:      save(unchanged, map[string]any{"smtpEncryption": "rot13"}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_encryption_invalid",
			english:    "Invalid SMTP encryption.",
			portuguese: "Criptografia SMTP inválida.",
		},
		{
			name:       "an SMTP username past the bound",
			serve:      save(unchanged, map[string]any{"smtpUsername": strings.Repeat("u", 61)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_username_too_long",
			english:    "SMTP username must be less than 60 characters.",
			portuguese: "O nome de usuário SMTP deve ter menos de 60 caracteres.",
		},
		{
			name:       "an SMTP password past the bound",
			serve:      save(unchanged, map[string]any{"smtpPassword": strings.Repeat("p", 257)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_password_too_long",
			english:    "SMTP password must be at most 256 bytes.",
			portuguese: "A senha SMTP deve ter no máximo 256 bytes.",
		},
		{
			name:       "an SMTP from name past the bound",
			serve:      save(unchanged, map[string]any{"smtpFromName": strings.Repeat("n", 61)}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_from_name_too_long",
			english:    "SMTP from name must be less than 60 characters.",
			portuguese: "O nome do remetente SMTP deve ter menos de 60 caracteres.",
		},
		{
			name:       "an SMTP from email past the bound",
			serve:      save(unchanged, map[string]any{"smtpFromEmail": strings.Repeat("e", 50) + "@example.com"}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_from_email_too_long",
			english:    "SMTP from email must be less than 60 characters.",
			portuguese: "O e-mail do remetente SMTP deve ter menos de 60 caracteres.",
		},
		{
			name:       "a new SMTP password and its removal at once",
			serve:      save(unchanged, map[string]any{"smtpPassword": "new-secret", "clearSmtpPassword": true}),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_password_and_clear",
			english:    "Send either a new SMTP password or clearSmtpPassword, not both.",
			portuguese: "Envie uma nova senha SMTP ou clearSmtpPassword, não os dois.",
		},
		{
			name:       "a host change keeping a stored password",
			serve:      save(emailSaveSettings(t, "smtp.example.test", true), nil),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.smtp_host_changed",
			english:    "The SMTP host has changed: enter the SMTP password again, or remove it.",
			portuguese: "O host SMTP foi alterado: digite a senha SMTP novamente ou remova-a.",
		},
		{
			name: "a refused connectivity dial",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				return save(unchanged, map[string]any{"smtpPort": unreachableSMTPPort(t)})(t, acceptLanguage)
			},
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.connect_failed_refused",
			english:    "Unable to connect to the SMTP server: connection refused.",
			portuguese: "Não foi possível conectar ao servidor SMTP: conexão recusada.",
		},
		{
			name:       "a test send with SMTP off",
			serve:      sendTest(&record.Settings{}, "admin@example.com"),
			status:     http.StatusBadRequest,
			code:       "SMTP_NOT_ENABLED",
			english:    "SMTP is not enabled",
			portuguese: "O SMTP não está habilitado",
		},
		{
			name:       "a test send with no destination",
			serve:      sendTest(&record.Settings{SMTPEnabled: true}, " "),
			status:     http.StatusBadRequest,
			code:       "handler.settings_email.destination_required",
			english:    "Destination email is required.",
			portuguese: "O e-mail de destino é obrigatório.",
		},
	})
}

// TestSettingsEmailSendFailures_AreInTheRequestsLanguage covers every answer of a failed test send:
// the four a connection's coarse cause chooses and the seven the sender's kinds choose, each a whole
// sentence of its own.
func TestSettingsEmailSendFailures_AreInTheRequestsLanguage(t *testing.T) {
	failing := func(kind emaildelivery.SendFailureKind, cause error) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			emailSender := accounthandlersmocks.NewEmailSender(t)
			emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
				Return(errs.WithStack(&emaildelivery.SendError{Kind: kind, Err: cause})).Once()
			r := sendTestEmailRequest(t, &record.Settings{SMTPEnabled: true})
			rr := httptest.NewRecorder()
			HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender, handlersmocks.NewAuditLogger(t)).
				ServeHTTP(rr, inRequestLanguage(r, acceptLanguage))
			return rr
		}
	}
	serverText := errs.New("535 5.7.8 no")
	sendFailed := func(name string, kind emaildelivery.SendFailureKind, cause error, english, portuguese string) refusalCase {
		return refusalCase{name: name, serve: failing(kind, cause), status: http.StatusBadRequest, code: "SEND_FAILED",
			english: english, portuguese: portuguese}
	}

	assertRefusalLanguages(t, []refusalCase{
		sendFailed("a host name not found", emaildelivery.SendFailureConnection,
			&net.DNSError{Err: "no such host", Name: "smtp.example.com", IsNotFound: true},
			"Unable to send the test email: host name not found.",
			"Não foi possível enviar o e-mail de teste: nome do host não encontrado."),
		sendFailed("a connection that timed out", emaildelivery.SendFailureConnection, os.ErrDeadlineExceeded,
			"Unable to send the test email: connection timed out.",
			"Não foi possível enviar o e-mail de teste: tempo de conexão esgotado."),
		sendFailed("a refused connection", emaildelivery.SendFailureConnection,
			&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
			"Unable to send the test email: connection refused.",
			"Não foi possível enviar o e-mail de teste: conexão recusada."),
		sendFailed("a connection failure with no cause the classification names", emaildelivery.SendFailureConnection,
			&os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
			"Unable to send the test email.",
			"Não foi possível enviar o e-mail de teste."),
		sendFailed("STARTTLS not offered", emaildelivery.SendFailureSTARTTLSNotOffered, serverText,
			"The SMTP server did not offer STARTTLS; set the encryption to None only if the server has no TLS.",
			"O servidor SMTP não ofereceu STARTTLS; defina a criptografia como Nenhuma apenas se o servidor não tiver TLS."),
		sendFailed("a password that would go unencrypted", emaildelivery.SendFailureUnencryptedPassword, serverText,
			"The SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS.",
			"O servidor SMTP receberia a senha sem criptografia; defina a criptografia como STARTTLS ou SSL/TLS."),
		sendFailed("credentials configured and no authentication offered", emaildelivery.SendFailureNoAuthentication, serverText,
			"SMTP credentials are configured but the server offers no authentication.",
			"Há credenciais SMTP configuradas, mas o servidor não oferece autenticação."),
		sendFailed("no supported mechanism", emaildelivery.SendFailureNoSupportedMechanism, serverText,
			"The SMTP server offers none of PLAIN, LOGIN or CRAM-MD5.",
			"O servidor SMTP não oferece nenhum de PLAIN, LOGIN ou CRAM-MD5."),
		sendFailed("a failed TLS handshake", emaildelivery.SendFailureTLS, serverText,
			"The TLS connection failed; check the encryption setting and the server's certificate.",
			"A conexão TLS falhou; verifique a configuração de criptografia e o certificado do servidor."),
		sendFailed("rejected credentials", emaildelivery.SendFailureAuthenticationRejected, serverText,
			"The SMTP server rejected the username or password.",
			"O servidor SMTP rejeitou o nome de usuário ou a senha."),
		sendFailed("a refused message", emaildelivery.SendFailureMessageRefused, serverText,
			"The SMTP server refused the message.",
			"O servidor SMTP recusou a mensagem."),
		sendFailed("anything else", emaildelivery.SendFailureOther, serverText,
			"Unable to send the test email.",
			"Não foi possível enviar o e-mail de teste."),
	})
}

// TestSettingsEmailDialFailures_AreWholeSentences covers the connectivity dial's answers the handler
// cannot be made to produce on every machine alike, a host not found, a dial that timed out and one
// with no cause the classification names, in pt-BR. TestConnectionFailureMessage pins the English.
func TestSettingsEmailDialFailures_AreWholeSentences(t *testing.T) {
	ctx := inRequestLanguage(httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/email", nil), "pt-BR").Context()
	for cause, want := range map[emaildelivery.ConnectionCause]string{
		emaildelivery.ConnectionCauseHostNotFound: "Não foi possível conectar ao servidor SMTP: nome do host não encontrado.",
		emaildelivery.ConnectionCauseTimedOut:     "Não foi possível conectar ao servidor SMTP: tempo de conexão esgotado.",
		emaildelivery.ConnectionCauseRefused:      "Não foi possível conectar ao servidor SMTP: conexão recusada.",
		emaildelivery.ConnectionCauseNone:         "Não foi possível conectar ao servidor SMTP.",
	} {
		require.Equal(t, want, connectionFailureMessage(smtpDialFailure, cause).Localize(ctx))
	}
}
