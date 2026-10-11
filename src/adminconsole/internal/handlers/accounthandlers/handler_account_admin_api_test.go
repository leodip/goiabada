package accounthandlers

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// Every account page is driven here through the real API client against an auth server that
// answers as the auth server answers a token carrying authserver:manage-account alone (#563
// decision 3).
//
// The console's other handler tests hand a handler a fake that checks no scope, and a token is a
// string to them, so a page asking the admin API passed every one of them and failed for every user
// who was not an administrator: the Account → Phone page asked GET /api/v1/admin/phone-countries for
// its country list, the auth server refused that user's token with 403 INSUFFICIENT_SCOPE, and the
// console answered its "Server error" page. Here the admin API answers that 403 and the request
// fails the test, naming the route, so the next account page calling an admin route fails the unit
// tier rather than a user.
//
// Each handler runs twice: once with every account write accepted, so the handler runs to its end,
// and once with every write refused as a form error, so a call made only when a refused form is
// re-rendered is made too.

// refusedFormDescription is the sentence the stub refuses an account write with, which a page
// re-renders its form under.
const refusedFormDescription = "The auth server refused the form."

// manageAccountAuthServer is the stub. replies overrides the minimal reply of an account route,
// keyed "METHOD /path"; refuseWrites answers every account write with a 400.
type manageAccountAuthServer struct {
	replies      map[string]string
	refuseWrites bool
}

// minimalAccountReplies are the account routes whose minimal reply is more than an empty object:
// the session list the end-session POST finds its session in, the end of that session, which the
// client refuses without its success flag, and the logout request's answer, which the client
// refuses when it fills neither of its two shapes.
var minimalAccountReplies = map[string]string{
	"GET /api/v1/account/sessions":        `{"sessions":[{"id":31}]}`,
	"DELETE /api/v1/account/sessions/31":  `{"success":true}`,
	"POST /api/v1/account/logout-request": `{"logoutUrl":"https://auth.example.test/auth/logout"}`,
}

// client starts the stub and returns the console's real API client pointed at it.
func (s manageAccountAuthServer) client(t *testing.T) *apiclient.AuthServerClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/admin/"):
			// What the auth server's route gate answers a token whose scopes the route does not
			// list: RequireBearerTokenScopeAnyOf, through the API's bearer refusals.
			t.Errorf("an account page asked the admin API, %s, which refuses a token carrying "+
				"authserver:manage-account alone", route)
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="goiabada", error="insufficient_scope", error_description="Insufficient scope."`)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error_code":"INSUFFICIENT_SCOPE","error_description":"Insufficient scope."}`)

		case !strings.HasPrefix(r.URL.Path, "/api/v1/account/"):
			t.Errorf("an account page asked %s, which is neither an account nor an admin route", route)
			w.WriteHeader(http.StatusNotFound)

		case s.refuseWrites && r.Method != http.MethodGet:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"error_code":"VALIDATION_ERROR","error_description":%q}`, refusedFormDescription)

		default:
			reply, ok := s.replies[route]
			if !ok {
				reply, ok = minimalAccountReplies[route]
			}
			if !ok {
				reply = `{}`
			}
			_, _ = fmt.Fprint(w, reply)
		}
	}))
	t.Cleanup(server.Close)
	return apiclient.NewAuthServerClient(server.URL, nil)
}

// accountHandlersOutsideTheTable are the account handlers accountHandlerCases leaves out: the
// password page's GET, which consults no API, and the two picture handlers, which the
// request-context test builds apart.
func accountHandlersOutsideTheTable() []accountHandlerCase {
	return []accountHandlerCase{
		{
			name: "HandleChangePasswordGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleChangePasswordGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/change-password", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleProfilePicturePost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleProfilePicturePost(h, c)
			},
			request: func() *http.Request {
				var body bytes.Buffer
				writer := multipart.NewWriter(&body)
				part, err := writer.CreateFormFile("picture", "me.png")
				if err != nil {
					panic(err)
				}
				_, _ = part.Write([]byte("\x89PNG\r\n\x1a\n"))
				_ = writer.Close()
				return handlertest.Request(http.MethodPost, "/account/picture",
					handlertest.WithAccessToken(), handlertest.WithBody(&body),
					handlertest.WithContentType(writer.FormDataContentType()))
			},
		},
		{
			name: "HandleProfilePictureDelete",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleProfilePictureDelete(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodDelete, "/account/picture", handlertest.WithAccessToken())
			},
		},
	}
}

func TestAccountHandlers_NoAccountPageAsksTheAdminAPI(t *testing.T) {
	cases := accountHandlerCases()
	cases = append(cases, accountHandlersOutsideTheTable()...)

	for _, refuseWrites := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name + "/writes accepted"
			if refuseWrites {
				name = tc.name + "/writes refused"
			}
			t.Run(name, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				if refuseWrites {
					// A refused write ends a page without a form on its error page or its JSON
					// error, which is the classifier's business and not this test's.
					httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
					httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
				} else {
					// With every account route answering, a page that fails anyway asked
					// something that did not answer, and stopped before the calls after it.
					handlertest.RefuseInternalServerError(t, httpHelper)
					httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).
						Run(func(args mock.Arguments) {
							t.Errorf("the handler answered a JSON error: %v", args.Get(2))
						}).Maybe()
				}
				httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
				handlertest.ExpectRender(httpHelper, mock.Anything, mock.Anything).Maybe()

				apiClient := manageAccountAuthServer{refuseWrites: refuseWrites}.client(t)
				tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request())
			})
		}
	}
}
