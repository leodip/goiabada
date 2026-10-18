package apihandlers

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// A refusal a person reaches through the admin console is answered in the language the request
// names, and only its description changes: the error_code and the status are the ones the call site
// writes, whatever the language. A request naming no language reads exactly what it read before
// (#559 decisions 1 and 2).
//
// Each row is served twice, once with no Accept-Language and once with pt-BR, through the request
// locale the API branch's middleware resolves. The expected sentences are written out here, not
// read from the catalog, and the Portuguese one is held to differ from the English one, so an
// English fallback cannot pass for a translation.

// refusalCase is one refusal: how to provoke it, and what it answers in each language.
type refusalCase struct {
	name string
	// serve answers one request carrying acceptLanguage, "" for none.
	serve      func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder
	status     int
	code       string
	english    string
	portuguese string
}

// inRequestLanguage sets acceptLanguage on r and attaches the locale the API's middleware resolves
// from it: ui_locales, then Accept-Language, then English.
func inRequestLanguage(r *http.Request, acceptLanguage string) *http.Request {
	if acceptLanguage != "" {
		r.Header.Set("Accept-Language", acceptLanguage)
	}
	return r.WithContext(i18n.ResolveRequestLocale(r.Context(), r))
}

func assertRefusalLanguages(t *testing.T, cases []refusalCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NotEqual(t, c.english, c.portuguese, "the row must tell a translation from a fallback")

			for _, language := range []struct {
				name           string
				acceptLanguage string
				want           string
			}{
				{"no language", "", c.english},
				{"pt-BR", "pt-BR", c.portuguese},
			} {
				t.Run(language.name, func(t *testing.T) {
					rr := c.serve(t, language.acceptLanguage)

					assert.Equal(t, c.status, rr.Code, "the status does not depend on the language")
					code, description := decodeErrorEnvelope(t, rr)
					assert.Equal(t, c.code, code, "the error_code does not depend on the language")
					assert.Equal(t, language.want, description)
				})
			}
		})
	}
}

// TestWriteLocalizedError is the writer every converted refusal goes through: the description from
// the catalog in the request's language, the code and the status the caller names.
func TestWriteLocalizedError(t *testing.T) {
	assertRefusalLanguages(t, []refusalCase{
		{
			name: "a 400 keeps the caller's VALIDATION_ERROR",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				r := inRequestLanguage(httptest.NewRequest(http.MethodPost, "/api/v1/admin/resources", nil), acceptLanguage)
				writeLocalizedError(rr, r, i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil), "VALIDATION_ERROR", http.StatusBadRequest)
				return rr
			},
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Please enter a valid email address.",
			portuguese: "Informe um endereço de e-mail válido.",
		},
		{
			name: "a 409 keeps the caller's code and status, and the arguments reach the sentence",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				r := inRequestLanguage(httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/1/email", nil), acceptLanguage)
				writeLocalizedError(rr, r, i18n.NewLocalizedError(i18n.ErrCodeEmailTooLong, map[string]any{"max": 60}), "EMAIL_TOO_LONG", http.StatusConflict)
				return rr
			},
			status:     http.StatusConflict,
			code:       "EMAIL_TOO_LONG",
			english:    "The email address cannot exceed a maximum length of 60 characters.",
			portuguese: "O endereço de e-mail não pode ter mais que 60 caracteres.",
		},
	})
}

// TestSharedRefusals_AreInTheRequestsLanguage covers the refusals more than one area writes: the
// two list-save conflicts, the email race, the last administrator and the image upload's two.
func TestSharedRefusals_AreInTheRequestsLanguage(t *testing.T) {
	writer := func(write func(w http.ResponseWriter, r *http.Request)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			write(rr, inRequestLanguage(httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/7/permissions", nil), acceptLanguage))
			return rr
		}
	}
	upload := func(field string, data []byte, maxBytes int64) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			r, err := createMultipartRequest(http.MethodPost, "/api/v1/admin/users/1/profile-picture", field, data)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			_, ok := readUploadedImage(rr, inRequestLanguage(r, acceptLanguage), maxBytes)
			require.False(t, ok, "the upload must be refused")
			return rr
		}
	}

	assertRefusalLanguages(t, []refusalCase{
		{
			name: "a list changed after it was loaded",
			serve: writer(func(w http.ResponseWriter, r *http.Request) {
				writeListSaveFailure(w, r, errs.Wrap(errListChanged, "saving the list"))
			}),
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The list was changed by another save after it was loaded. Nothing was saved: reload it and make the change again.",
			portuguese: "A lista foi alterada por outro salvamento depois de ser carregada. Nada foi salvo: recarregue a lista e faça a alteração novamente.",
		},
		{
			name: "a list changed at the same moment",
			serve: writer(func(w http.ResponseWriter, r *http.Request) {
				writeListSaveFailure(w, r, errs.Wrap(data.ErrUniqueViolation, "inserting a row"))
			}),
			status:     http.StatusConflict,
			code:       "CONCURRENT_UPDATE",
			english:    "The list was changed by another save at the same moment. Nothing was saved: reload it and make the change again.",
			portuguese: "A lista foi alterada por outro salvamento no mesmo instante. Nada foi salvo: recarregue a lista e faça a alteração novamente.",
		},
		{
			name: "an email address taken by a concurrent write",
			serve: writer(func(w http.ResponseWriter, r *http.Request) {
				writeEmailTakenOrInternalServerError(w, r, errs.Wrap(data.ErrUniqueViolation, "updating the user"))
			}),
			status:     http.StatusConflict,
			code:       "EMAIL_ALREADY_EXISTS",
			english:    "This email address is already registered",
			portuguese: "Este endereço de e-mail já está cadastrado",
		},
		{
			name: "the last administrator",
			serve: writer(func(w http.ResponseWriter, r *http.Request) {
				writeLastAdministrator(w, r)
			}),
			status:     http.StatusConflict,
			code:       "LAST_ADMINISTRATOR",
			english:    "This change would leave no enabled user holding authserver:manage. Grant it to another user first.",
			portuguese: "Esta alteração não deixaria nenhum usuário habilitado com authserver:manage. Conceda essa permissão a outro usuário primeiro.",
		},
		{
			name:       "an upload past the bound",
			serve:      upload("picture", bytes.Repeat([]byte{0xAB}, 64+2048), 64),
			status:     http.StatusBadRequest,
			code:       "FILE_TOO_LARGE",
			english:    "File too large or invalid form data",
			portuguese: "Arquivo grande demais ou dados de formulário inválidos",
		},
		{
			name:       "an upload with no picture part",
			serve:      upload("avatar", createTestPNG(100, 100), testMaxUploadBytes),
			status:     http.StatusBadRequest,
			code:       "NO_FILE",
			english:    "No picture file provided",
			portuguese: "Nenhum arquivo de foto foi enviado",
		},
	})
}

// TestResourceRefusals_AreInTheRequestsLanguage covers every refusal of the resource endpoints a
// person can reach; the missing or malformed resource id and the body that does not parse are an
// integrator's, and stay English.
func TestResourceRefusals_AreInTheRequestsLanguage(t *testing.T) {
	system := func() *record.Resource {
		return &record.Resource{Id: 1, ResourceIdentifier: builtin.AuthServerResourceIdentifier}
	}
	ordinary := func() *record.Resource {
		return &record.Resource{Id: 5, ResourceIdentifier: "a-resource", Description: "A resource"}
	}
	create := func(body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			if expect != nil {
				expect(database)
			}
			r := inRequestLanguage(httptest.NewRequest(http.MethodPost, "/api/v1/admin/resources", strings.NewReader(body)), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleResourceCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	update := func(stored *record.Resource, body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), stored.Id).Return(stored, nil).Once()
			if expect != nil {
				expect(database)
			}
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/x", strings.NewReader(body))
			r = inRequestLanguage(setChiURLParam(r, "id", strconv.FormatInt(stored.Id, 10)), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleResourceUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	identifierHeldBy := func(identifier string, holder *record.Resource) func(database *datamocks.Database) {
		return func(database *datamocks.Database) {
			database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), identifier).Return(holder, nil).Once()
		}
	}
	longDescription := strings.Repeat("a", 101)

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "create with no identifier",
			serve:      create(`{"resourceIdentifier":"  ","description":"d"}`, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Resource identifier is required",
			portuguese: "O identificador do recurso é obrigatório",
		},
		{
			name:       "create with a description past the bound",
			serve:      create(`{"resourceIdentifier":"a-resource","description":"`+longDescription+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The description cannot exceed a maximum length of 100 characters",
			portuguese: "A descrição não pode ter mais que 100 caracteres",
		},
		{
			name:       "create with an identifier in use",
			serve:      create(`{"resourceIdentifier":"a-resource","description":"d"}`, identifierHeldBy("a-resource", ordinary())),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The resource identifier is already in use",
			portuguese: "O identificador do recurso já está em uso",
		},
		{
			name: "create naming a client's identifier",
			serve: create(`{"resourceIdentifier":"a-resource","description":"d"}`, func(database *datamocks.Database) {
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "a-resource").Return(nil, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "a-resource").Return(&record.Client{Id: 8, ClientIdentifier: "a-resource"}, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The resource identifier is already in use by a client",
			portuguese: "O identificador do recurso já está em uso por um cliente",
		},
		{
			name:       "update with no identifier",
			serve:      update(ordinary(), `{"resourceIdentifier":"","description":"d"}`, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Resource identifier is required",
			portuguese: "O identificador do recurso é obrigatório",
		},
		{
			name:       "update with a description past the bound",
			serve:      update(ordinary(), `{"resourceIdentifier":"a-resource","description":"`+longDescription+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The description cannot exceed a maximum length of 100 characters",
			portuguese: "A descrição não pode ter mais que 100 caracteres",
		},
		{
			name: "update onto another resource's identifier",
			serve: update(ordinary(), `{"resourceIdentifier":"other-resource","description":"d"}`,
				identifierHeldBy("other-resource", &record.Resource{Id: 6, ResourceIdentifier: "other-resource"})),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The resource identifier is already in use",
			portuguese: "O identificador do recurso já está em uso",
		},
		{
			name: "update onto a client's identifier",
			serve: update(ordinary(), `{"resourceIdentifier":"named-like-a-client","description":"d"}`, func(database *datamocks.Database) {
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "named-like-a-client").Return(nil, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "named-like-a-client").Return(&record.Client{Id: 8, ClientIdentifier: "named-like-a-client"}, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The resource identifier is already in use by a client",
			portuguese: "O identificador do recurso já está em uso por um cliente",
		},
		{
			name:       "update renaming the system resource",
			serve:      update(system(), `{"resourceIdentifier":"renamed-system","description":"d"}`, identifierHeldBy("renamed-system", nil)),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The identifier of a system-level resource cannot be changed.",
			portuguese: "O identificador de um recurso em nível de sistema não pode ser alterado.",
		},
		{
			name: "delete of the system resource",
			serve: func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
				database := datamocks.NewDatabase(t)
				database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(system(), nil).Once()
				r := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/resources/1", nil)
				r = inRequestLanguage(setChiURLParam(r, "id", "1"), acceptLanguage)
				rr := httptest.NewRecorder()
				HandleResourceDelete(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
				return rr
			},
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Trying to delete a system level resource",
			portuguese: "Tentativa de excluir um recurso em nível de sistema",
		},
	})
}

// TestResourcePermissionRefusals_AreInTheRequestsLanguage covers every refusal of the resource
// permissions save a person can reach; the resource id, the body and the missing
// expectedPermissions are an integrator's, and stay English.
func TestResourcePermissionRefusals_AreInTheRequestsLanguage(t *testing.T) {
	stored := resourcePermsStored()
	loaded := loadedEntries(stored)

	builtIns := make([]record.Permission, 0, len(builtin.AuthServerPermissionIdentifiers()))
	for i, identifier := range builtin.AuthServerPermissionIdentifiers() {
		builtIns = append(builtIns, record.Permission{Id: int64(40 + i), ResourceId: resourcePermsId, PermissionIdentifier: identifier, Description: identifier})
	}
	manage := -1
	for i, p := range builtIns {
		if p.PermissionIdentifier == builtin.ManagePermissionIdentifier {
			manage = i
		}
	}
	require.GreaterOrEqual(t, manage, 0)

	save := func(resourceIdentifier string, checked []record.Permission, permissions, expected []api.ResourcePermissionUpsert) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			expectResourcePermsResource(database, resourceIdentifier)
			if checked != nil {
				expectResourcePermsChecked(database, checked)
			}
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/7/permissions", strings.NewReader(resourcePermsBody(t, permissions, expected)))
			r = inRequestLanguage(setChiURLParam(r, "resourceId", "7"), acceptLanguage)
			rr := httptest.NewRecorder()
			HandleResourcePermissionsPut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
			return rr
		}
	}
	withoutManage := slices.Delete(loadedEntries(builtIns), manage, manage+1)
	manageRenamed := loadedEntries(builtIns)
	manageRenamed[manage].PermissionIdentifier = "manage-renamed"

	assertRefusalLanguages(t, []refusalCase{
		{
			name: "two entries naming one stored permission",
			serve: save("a-resource", nil, []api.ResourcePermissionUpsert{
				{Id: 31, PermissionIdentifier: "read", Description: "Read"},
				{Id: 31, PermissionIdentifier: "read-again", Description: "Read"},
			}, loaded),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Duplicate permission IDs in request are not allowed",
			portuguese: "IDs de permissão duplicados não são permitidos na requisição",
		},
		{
			name:       "an entry with no identifier",
			serve:      save("a-resource", nil, []api.ResourcePermissionUpsert{{PermissionIdentifier: " ", Description: "d"}}, loaded),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Permission identifier is required",
			portuguese: "O identificador da permissão é obrigatório",
		},
		{
			name:       "an entry with a description past the bound",
			serve:      save("a-resource", nil, []api.ResourcePermissionUpsert{{PermissionIdentifier: "read", Description: strings.Repeat("a", 101)}}, loaded),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "The description cannot exceed a maximum length of 100 characters.",
			portuguese: "A descrição não pode ter mais que 100 caracteres.",
		},
		{
			name: "two entries with one identifier",
			serve: save("a-resource", nil, []api.ResourcePermissionUpsert{
				{PermissionIdentifier: "audit", Description: "Audit"},
				{PermissionIdentifier: "audit", Description: "Audit again"},
			}, loaded),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Permission audit is duplicated.",
			portuguese: "A permissão audit está duplicada.",
		},
		{
			name:       "the system resource's list without manage",
			serve:      save(builtin.AuthServerResourceIdentifier, builtIns, withoutManage, loadedEntries(builtIns)),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Built-in permission 'manage' cannot be deleted.",
			portuguese: "A permissão nativa 'manage' não pode ser excluída.",
		},
		{
			name:       "the system resource's list with manage renamed",
			serve:      save(builtin.AuthServerResourceIdentifier, builtIns, manageRenamed, loadedEntries(builtIns)),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Built-in permission 'manage' cannot be renamed.",
			portuguese: "A permissão nativa 'manage' não pode ser renomeada.",
		},
		{
			name:       "a new permission reusing a stored identifier",
			serve:      save("a-resource", stored, []api.ResourcePermissionUpsert{{PermissionIdentifier: "read", Description: "Read again"}}, loaded),
			status:     http.StatusBadRequest,
			code:       "VALIDATION_ERROR",
			english:    "Permission identifier read is already in use.",
			portuguese: "O identificador de permissão read já está em uso.",
		},
	})
}
