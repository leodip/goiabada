// Package handlertest carries the wiring every admin console handler test builds by hand: the
// values a handler reads off its request context, the chi route parameters its URL carries, and
// the expectations and call-log reads its rendering performs against the HttpHelper mock.
//
// It is a sibling of internal/handlers rather than a child on purpose. The slog convention guard
// and the dead-interface guard both key on the adminconsole/internal/handlers path, and neither
// has anything to say about test support; a child package would be swept into both (#350).
//
// It holds no assertions of its own about any handler. Everything here builds an input or reads an
// output back, so a case that adopts it asserts exactly what it asserted before.
package handlertest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// AccessToken is the bearer WithAccessToken puts on the context. Every admin console handler test
// used the same literal before this package existed, and the one case that asserts which token
// reached the API client reads it from here rather than repeating it.
const AccessToken = "an-access-token"

// Option adjusts what Request builds. An option that is not given leaves its value off the request
// entirely, which is the distinction the tables covering an unauthenticated visitor depend on:
// without WithAccessToken there is no token set at all, not an empty one.
type Option func(*requestSpec)

type requestSpec struct {
	body        io.Reader
	contentType string
	routeParams [][2]string
	accessToken *string
	jwtInfo     *oauthclient.JwtInfo
	settings    *api.PublicSettingsResponse
	hasSettings bool
}

// Request builds a request carrying what the options ask for and nothing else. Its context is
// Background with those values on it, as httptest.NewRequest's would be: a test has no request
// above it whose context this one could inherit.
func Request(method, target string, opts ...Option) *http.Request {
	spec := &requestSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	req := httptest.NewRequestWithContext(context.Background(), method, target, spec.body)
	if spec.contentType != "" {
		req.Header.Set("Content-Type", spec.contentType)
	}

	ctx := req.Context()
	if len(spec.routeParams) > 0 {
		routeCtx := chi.NewRouteContext()
		for _, param := range spec.routeParams {
			routeCtx.URLParams.Add(param[0], param[1])
		}
		ctx = context.WithValue(ctx, chi.RouteCtxKey, routeCtx)
	}
	if spec.jwtInfo != nil {
		ctx = reqctx.WithJwtInfo(ctx, *spec.jwtInfo)
	} else if spec.accessToken != nil {
		ctx = reqctx.WithJwtInfo(ctx,
			oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: *spec.accessToken}})
	}
	if spec.hasSettings {
		ctx = reqctx.WithSettings(ctx, spec.settings)
	}
	return req.WithContext(ctx)
}

// WithAccessToken puts a token set carrying AccessToken on the context, which is where every admin
// console handler reads the bearer it forwards to the API. Without it a handler answers 500
// before reaching anything most cases are about.
func WithAccessToken() Option {
	return func(spec *requestSpec) {
		token := AccessToken
		spec.accessToken = &token
	}
}

// WithJwtInfo puts a whole oauthclient.JwtInfo on the context, for the handlers that read the
// verified ID token rather than the raw bearer alone. WithAccessToken fills
// TokenResponse.AccessToken and leaves IdToken nil, which is indistinguishable from a visitor who
// never authenticated: the logout page, which requires both, takes its unauthenticated arm.
//
// It replaces whatever WithAccessToken set, so the two are not combined.
func WithJwtInfo(jwtInfo oauthclient.JwtInfo) Option {
	return func(spec *requestSpec) {
		spec.jwtInfo = &jwtInfo
	}
}

// WithRouteParam adds one chi URL parameter, as the router would have parsed it from the pattern.
// A handler reached through chi.NewRouter() needs none of these; a handler called directly, which
// is most of them, reads an empty string for every parameter without them.
func WithRouteParam(key, value string) Option {
	return func(spec *requestSpec) {
		spec.routeParams = append(spec.routeParams, [2]string{key, value})
	}
}

// WithSettings puts the settings on the context through reqctx, as the settings-cache middleware
// does in production.
func WithSettings(settings *api.PublicSettingsResponse) Option {
	return func(spec *requestSpec) {
		spec.settings = settings
		spec.hasSettings = true
	}
}

// WithForm gives the request a form-encoded body and the header that declares it, which together
// are what the handlers read through r.PostFormValue.
func WithForm(form url.Values) Option {
	return func(spec *requestSpec) {
		WithBody(strings.NewReader(form.Encode()))(spec)
		WithContentType("application/x-www-form-urlencoded")(spec)
	}
}

// WithBody gives the request a body and no Content-Type, which is what the AJAX endpoints reading
// a JSON entity off r.Body receive from the console's own scripts.
func WithBody(body io.Reader) Option {
	return func(spec *requestSpec) {
		spec.body = body
	}
}

// WithContentType declares the body's media type.
func WithContentType(contentType string) Option {
	return func(spec *requestSpec) {
		spec.contentType = contentType
	}
}
