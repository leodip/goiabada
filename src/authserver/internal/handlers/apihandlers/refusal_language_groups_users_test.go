package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The refusals of groups, their attributes and members, and of users, their attributes, groups and
// email verification code, served once with no language and once in pt-BR through
// assertRefusalLanguages (#559 decisions 1 and 2). The missing or malformed ids, the body that does
// not parse and the missing expectedGroupIds are an integrator's, and stay English. Every other
// refusal answers its catalog key as its error_code, which the console reads the field off (#617).

// TestGroupRefusals_AreInTheRequestsLanguage covers the group endpoints' refusals.
func TestGroupRefusals_AreInTheRequestsLanguage(t *testing.T) {
	stored := func() *record.Group { return &record.Group{Id: 5, GroupIdentifier: "a-group", Description: "A group"} }
	create := func(body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			if expect != nil {
				expect(database)
			}
			r := inRequestLanguage(httptest.NewRequest(http.MethodPost, "/api/v1/admin/groups", strings.NewReader(body)), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleGroupCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	update := func(body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetGroupById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(stored(), nil).Once()
			if expect != nil {
				expect(database)
			}
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/groups/5", strings.NewReader(body))
			r = inRequestLanguage(setChiURLParam(r, "id", "5"), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleGroupUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	identifierHeldBy := func(identifier string, holder *record.Group) func(database *datamocks.Database) {
		return func(database *datamocks.Database) {
			database.On("GetGroupByGroupIdentifier", mock.Anything, (*sql.Tx)(nil), identifier).Return(holder, nil).Once()
		}
	}
	longDescription := strings.Repeat("a", 101)

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "create with no identifier",
			serve:      create(`{"groupIdentifier":" ","description":"d"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.group.identifier_required",
			english:    "Group identifier is required",
			portuguese: "O identificador do grupo é obrigatório",
		},
		{
			name:       "create with a description past the bound",
			serve:      create(`{"groupIdentifier":"a-group","description":"`+longDescription+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.group.description_too_long",
			english:    "The description cannot exceed a maximum length of 100 characters",
			portuguese: "A descrição não pode ter mais que 100 caracteres",
		},
		{
			name:       "create with an identifier in use",
			serve:      create(`{"groupIdentifier":"a-group","description":"d"}`, identifierHeldBy("a-group", stored())),
			status:     http.StatusBadRequest,
			code:       "handler.group.identifier_in_use",
			english:    "The group identifier is already in use",
			portuguese: "O identificador do grupo já está em uso",
		},
		{
			name:       "update with no identifier",
			serve:      update(`{"groupIdentifier":"","description":"d"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.group.identifier_required",
			english:    "Group identifier is required",
			portuguese: "O identificador do grupo é obrigatório",
		},
		{
			name:       "update with a description past the bound",
			serve:      update(`{"groupIdentifier":"a-group","description":"`+longDescription+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.group.description_too_long",
			english:    "The description cannot exceed a maximum length of 100 characters",
			portuguese: "A descrição não pode ter mais que 100 caracteres",
		},
		{
			name: "update onto another group's identifier",
			serve: update(`{"groupIdentifier":"other-group","description":"d"}`,
				identifierHeldBy("other-group", &record.Group{Id: 6, GroupIdentifier: "other-group"})),
			status:     http.StatusBadRequest,
			code:       "handler.group.identifier_in_use",
			english:    "The group identifier is already in use",
			portuguese: "O identificador do grupo já está em uso",
		},
	})
}

// TestGroupMemberRefusals_AreInTheRequestsLanguage covers adding a member twice and removing one
// who is not a member, which two administrators reach by acting on the same group at once.
func TestGroupMemberRefusals_AreInTheRequestsLanguage(t *testing.T) {
	membership := func(existing *record.UserGroup) func(database *datamocks.Database) {
		return func(database *datamocks.Database) {
			expectGroup(database, 5)
			expectMember(database)
			database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId, int64(5)).
				Return(existing, nil).Once()
		}
	}
	serve := func(method, target, body string, params map[string]string, existing *record.UserGroup,
		handler func(database *datamocks.Database) http.Handler) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			membership(existing)(database)
			r := inRequestLanguage(membershipRequest(method, target, body, "authserver:manage", params), acceptLanguage)
			rr := httptest.NewRecorder()
			handler(database).ServeHTTP(rr, r)
			return rr
		}
	}
	member := strconv.FormatInt(ceilingMemberId, 10)

	assertRefusalLanguages(t, []refusalCase{
		{
			name: "adding a member twice",
			serve: serve(http.MethodPost, "/api/v1/admin/groups/5/members", `{"userId":`+member+`}`,
				map[string]string{"id": "5"}, &record.UserGroup{Id: 9, UserId: ceilingMemberId, GroupId: 5},
				func(database *datamocks.Database) http.Handler {
					return HandleGroupMemberAddPost(database, handlersmocks.NewAuditLogger(t))
				}),
			status:     http.StatusBadRequest,
			code:       "handler.group_member.already_member",
			english:    "User is already a member of this group",
			portuguese: "O usuário já é membro deste grupo",
		},
		{
			name: "removing someone who is not a member",
			serve: serve(http.MethodDelete, "/api/v1/admin/groups/5/members/"+member, "",
				map[string]string{"id": "5", "userId": member}, nil,
				func(database *datamocks.Database) http.Handler {
					return HandleGroupMemberDelete(database, handlersmocks.NewAuditLogger(t))
				}),
			status:     http.StatusBadRequest,
			code:       "handler.group_member.not_member",
			english:    "User is not a member of this group",
			portuguese: "O usuário não é membro deste grupo",
		},
	})
}

// TestAttributeRefusals_AreInTheRequestsLanguage covers a group's and a user's attributes, which
// say the same two sentences under the codes each always wrote: the key is the one the console's
// own check already says, and the value bound is one sentence for both.
func TestAttributeRefusals_AreInTheRequestsLanguage(t *testing.T) {
	longValue := strings.Repeat("v", 251)

	groupCreate := func(body string) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			r := inRequestLanguage(httptest.NewRequest(http.MethodPost, "/api/v1/admin/groups/attributes", strings.NewReader(body)), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleGroupAttributeCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	groupUpdate := func(body string) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetGroupAttributeById", mock.Anything, (*sql.Tx)(nil), int64(3)).
				Return(&record.GroupAttribute{Id: 3, GroupId: 5, Key: "k", Value: "v"}, nil).Once()
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/groups/attributes/3", strings.NewReader(body))
			r = inRequestLanguage(setChiURLParam(r, "id", "3"), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleGroupAttributeUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	userCreate := func(body string, readsUser bool) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			if readsUser {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&record.User{Id: 7}, nil).Once()
			}
			r := inRequestLanguage(httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/attributes", strings.NewReader(body)), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleUserAttributeCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	userUpdate := func(body string) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetUserAttributeById", mock.Anything, (*sql.Tx)(nil), int64(4)).
				Return(&record.UserAttribute{Id: 4, UserId: 7, Key: "k", Value: "v"}, nil).Once()
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/attributes/4", strings.NewReader(body))
			r = inRequestLanguage(setChiURLParam(r, "id", "4"), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleUserAttributeUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}

	const (
		keyEnglish      = "Attribute key is required"
		keyPortuguese   = "A chave do atributo é obrigatória"
		valueEnglish    = "The attribute value cannot exceed a maximum length of 250 characters"
		valuePortuguese = "O valor do atributo não pode ter mais que 250 caracteres"
	)
	assertRefusalLanguages(t, []refusalCase{
		{
			name: "a group attribute created with no key", serve: groupCreate(`{"groupId":5,"key":"","value":"v"}`),
			status: http.StatusBadRequest, code: "handler.attribute.key_required", english: keyEnglish, portuguese: keyPortuguese,
		},
		{
			// The group's id rides in the body here, not in the path, so it is no integrator's
			// malformed target and is translated (#559 decision 1).
			name: "a group attribute created with no group id", serve: groupCreate(`{"key":"tier","value":"gold"}`),
			status: http.StatusBadRequest, code: "handler.group_attribute.group_id_required", english: "Group ID is required", portuguese: "O ID do grupo é obrigatório",
		},
		{
			name: "a group attribute created with a value past the bound", serve: groupCreate(`{"groupId":5,"key":"k","value":"` + longValue + `"}`),
			status: http.StatusBadRequest, code: "handler.attribute.value_too_long", english: valueEnglish, portuguese: valuePortuguese,
		},
		{
			name: "a group attribute updated with no key", serve: groupUpdate(`{"key":"","value":"v"}`),
			status: http.StatusBadRequest, code: "handler.attribute.key_required", english: keyEnglish, portuguese: keyPortuguese,
		},
		{
			name: "a group attribute updated with a value past the bound", serve: groupUpdate(`{"key":"k","value":"` + longValue + `"}`),
			status: http.StatusBadRequest, code: "handler.attribute.value_too_long", english: valueEnglish, portuguese: valuePortuguese,
		},
		{
			name: "a user attribute created with no key", serve: userCreate(`{"userId":7,"key":"","value":"v"}`, false),
			status: http.StatusBadRequest, code: "handler.attribute.key_required", english: keyEnglish, portuguese: keyPortuguese,
		},
		{
			name: "a user attribute created with a value past the bound", serve: userCreate(`{"userId":7,"key":"k","value":"`+longValue+`"}`, true),
			status: http.StatusBadRequest, code: "VALUE_TOO_LONG", english: valueEnglish, portuguese: valuePortuguese,
		},
		{
			name: "a user attribute updated with no key", serve: userUpdate(`{"key":"","value":"v"}`),
			status: http.StatusBadRequest, code: "handler.attribute.key_required", english: keyEnglish, portuguese: keyPortuguese,
		},
		{
			name: "a user attribute updated with a value past the bound", serve: userUpdate(`{"key":"k","value":"` + longValue + `"}`),
			status: http.StatusBadRequest, code: "VALUE_TOO_LONG", english: valueEnglish, portuguese: valuePortuguese,
		},
	})
}

// TestUserRefusals_AreInTheRequestsLanguage covers creating a user, setting a password, disabling
// two-factor authentication, saving a user's groups and generating an email verification code.
func TestUserRefusals_AreInTheRequestsLanguage(t *testing.T) {
	createUser := func(payload map[string]any, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			if expect != nil {
				expect(database)
			}
			handler := HandleUserCreatePost(handlersmocks.NewPageRenderer(t), database, accounthandlersmocks.NewUserCreator(t),
				accountvalidation.NewEmailValidator(database),
				accountvalidation.NewProfileValidator(database),
				accountvalidation.NewPasswordValidator(),
				handlersmocks.NewAuditLogger(t), accounthandlersmocks.NewEmailSender(t), testDataCipher, testBaseURL)
			body, err := json.Marshal(payload)
			require.NoError(t, err)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewReader(body))
			r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "TestApp", SMTPEnabled: true, PasswordPolicy: record.PasswordPolicyLow}))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, inRequestLanguage(r, acceptLanguage))
			return rr
		}
	}
	noUserHolds := func(email string) func(database *datamocks.Database) {
		return func(database *datamocks.Database) {
			database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), email).Return(nil, nil).Once()
		}
	}
	userRequest := func(method, target, body string, acceptLanguage string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r = setTokenContextWithClaims(setChiURLParam(r, "id", "73"), map[string]any{"scope": "authserver:manage", "sub": adminSubject})
		return inRequestLanguage(r, acceptLanguage)
	}
	disableOTP := func(body string, stored *record.User) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			if stored != nil {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(73)).Return(stored, nil).Once()
			}
			rr := httptest.NewRecorder()
			HandleUserOTPPut(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, userRequest(http.MethodPut, "/api/v1/admin/users/73/otp", body, acceptLanguage))
			return rr
		}
	}
	tooManyGroups := make([]string, maxGroupIdsPerRequest+1)
	for i := range tooManyGroups {
		tooManyGroups[i] = strconv.Itoa(i + 1)
	}

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "a user created with no email",
			serve:      createUser(map[string]any{"email": "", "setPasswordType": "now", "password": "a-long-enough-password-1"}, nil),
			status:     http.StatusBadRequest,
			code:       "handler.user.email_required",
			english:    "Email is required",
			portuguese: "O e-mail é obrigatório",
		},
		{
			name:       "a user created with an email past the bound",
			serve:      createUser(map[string]any{"email": strings.Repeat("a", 49) + "@example.com"}, nil),
			status:     http.StatusBadRequest,
			code:       "EMAIL_TOO_LONG",
			english:    "The email address cannot exceed a maximum length of 60 characters",
			portuguese: "O endereço de e-mail não pode ter mais que 60 caracteres",
		},
		{
			name:       "a user created with an unknown setPasswordType",
			serve:      createUser(map[string]any{"email": "new@example.com", "setPasswordType": "later"}, noUserHolds("new@example.com")),
			status:     http.StatusBadRequest,
			code:       "handler.user.set_password_type_invalid",
			english:    `setPasswordType must be "now" or "email"`,
			portuguese: `setPasswordType deve ser "now" ou "email"`,
		},
		{
			name:       "a user created with no password",
			serve:      createUser(map[string]any{"email": "new@example.com", "setPasswordType": "now"}, noUserHolds("new@example.com")),
			status:     http.StatusBadRequest,
			code:       "handler.user.password_required",
			english:    "Password is required",
			portuguese: "A senha é obrigatória",
		},
		{
			name: "a password set to nothing",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				HandleUserPasswordPut(datamocks.NewDatabase(t), accountvalidation.NewPasswordValidator(), handlersmocks.NewAuditLogger(t)).
					ServeHTTP(rr, userRequest(http.MethodPut, "/api/v1/admin/users/73/password", `{"newPassword":""}`, acceptLanguage))
				return rr
			},
			status:     http.StatusBadRequest,
			code:       "handler.user.new_password_required",
			english:    "New password is required",
			portuguese: "A nova senha é obrigatória",
		},
		{
			name:       "two-factor authentication enabled by an administrator",
			serve:      disableOTP(`{"enabled":true}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.user.otp_enable_not_supported",
			english:    "Enabling OTP is not supported through this endpoint",
			portuguese: "Não é possível habilitar o OTP por este endpoint",
		},
		{
			name:       "two-factor authentication disabled for a user who has none",
			serve:      disableOTP(`{"enabled":false}`, &record.User{Id: 73, Subject: "sub-73", OTPEnabled: false}),
			status:     http.StatusBadRequest,
			code:       "OTP_NOT_ENABLED",
			english:    "User does not have OTP enabled",
			portuguese: "O usuário não tem o OTP habilitado",
		},
		{
			name: "a user's groups saved with too many ids",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				body := `{"groupIds":[` + strings.Join(tooManyGroups, ",") + `],"expectedGroupIds":[]}`
				rr := httptest.NewRecorder()
				HandleUserGroupsPut(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t)).
					ServeHTTP(rr, userRequest(http.MethodPut, "/api/v1/admin/users/73/groups", body, acceptLanguage))
				return rr
			},
			status:     http.StatusBadRequest,
			code:       "handler.user_groups.too_many",
			english:    "Too many group ids",
			portuguese: "Há IDs de grupo demais na requisição",
		},
		{
			name: "an email verification code whose account changed while it was sent",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				database := datamocks.NewDatabase(t)
				expectCodeGenRead(database)
				database.On("TryIssueEmailVerificationCode", mock.Anything, mock.Anything, codeGenUserId, codeGenAddress,
					mock.Anything, mock.Anything).Return(false, nil).Once()
				rr := httptest.NewRecorder()
				HandleUserEmailVerificationCodePost(database, handlersmocks.NewAuditLogger(t), testDataCipher).
					ServeHTTP(rr, inRequestLanguage(codeGenRequest(), acceptLanguage))
				return rr
			},
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The account was changed by another request while the code was being sent. Nothing was sent: try again.",
			portuguese: "A conta foi alterada por outra requisição enquanto o código era enviado. Nada foi enviado: tente novamente.",
		},
	})
}
