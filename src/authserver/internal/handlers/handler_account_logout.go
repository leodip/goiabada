package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	oauthdb "github.com/leodip/goiabada/core/oauthdb"
	"github.com/pkg/errors"
)

func HandleAccountLogoutGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idTokenHint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint")

		if len(idTokenHint) == 0 {

			// if no id_token_hint is provided, render the logout consent page
			bind := map[string]interface{}{
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/logout_consent.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		doLogoutWithIdToken(w, r, httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)
	}
}

// renderAuthError renders the auth_error.html page with a localized title
// and message. i18n surface: A — RP-initiated logout error page.
func renderAuthError(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper, locErr *i18n.LocalizedError) {
	ctx := r.Context()
	bind := map[string]interface{}{
		"title": i18n.T(ctx, i18n.ErrCodeLogoutErrorTitle),
		"error": locErr.Localize(ctx),
	}
	err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// isEncryptedIDTokenHint reports whether the hint is a compact JWE (5
// dot-separated segments) rather than a compact JWS (3 segments). An encrypted
// hint must be decrypted with the client's key before validation; a plain
// signed hint is validated as-is. See OpenID Connect Core 1.0 §2 (an encrypted
// ID Token is a Nested JWT).
func isEncryptedIDTokenHint(hint string) bool {
	return strings.Count(hint, ".") == 4
}

// decryptIDTokenHint decrypts a JWE-encrypted id_token_hint. The token is a JWE
// (dir + A256GCM) whose key is derived from the client secret, per the scheme
// documented in integration/endpoints.mdx and implemented in
// encryption.DecryptIDTokenHintJWE. client_id selects which client's secret to
// use, as required by RP-Initiated Logout for symmetrically-encrypted hints.
func decryptIDTokenHint(idTokenHint, clientID string, database data.Database) (string, *i18n.LocalizedError) {
	client, err := database.GetClientByClientIdentifier(nil, clientID)
	if err != nil || client == nil {
		slog.Error("logout: client lookup failed", "clientId", clientID, "err", err)
		return "", i18n.NewLocalizedError(i18n.ErrCodeLogoutInvalidClient, nil)
	}

	clientSecret, err := encryption.DecryptData(client.ClientSecretEncrypted)
	if err != nil {
		slog.Error("logout: client secret decrypt failed", "err", err)
		return "", i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintDecryptFailed, nil)
	}

	decryptedToken, err := encryption.DecryptIDTokenHintJWE(idTokenHint, clientSecret)
	if err != nil {
		slog.Error("logout: id_token_hint decrypt failed", "err", err)
		return "", i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintDecryptFailed, nil)
	}

	return decryptedToken, nil
}

func validateClientAndRedirectURI(idToken *oauth.JwtToken, postLogoutRedirectURI string, database data.Database, clientId string) (*models.Client, *i18n.LocalizedError) {
	clientIdentifier := idToken.GetStringClaim("aud")
	if len(clientIdentifier) == 0 {
		return nil, i18n.NewLocalizedError(i18n.ErrCodeLogoutAudClaimMissing, nil)
	}

	client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil || client == nil {
		slog.Error("logout: client lookup failed", "clientIdentifier", clientIdentifier, "err", err)
		return nil, i18n.NewLocalizedError(i18n.ErrCodeLogoutInvalidClient, nil)
	}

	if len(clientId) > 0 && clientId != clientIdentifier {
		return nil, i18n.NewLocalizedError(i18n.ErrCodeLogoutClientIdMismatch, nil)
	}

	err = database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		slog.Error("logout: load redirect URIs failed", "clientIdentifier", clientIdentifier, "err", err)
		return nil, i18n.NewLocalizedError(i18n.ErrCodeLogoutInvalidPostLogoutRedirect, nil)
	}

	for _, uri := range client.RedirectURIs {
		if uri.URI == postLogoutRedirectURI {
			return client, nil
		}
	}

	return nil, i18n.NewLocalizedError(i18n.ErrCodeLogoutInvalidPostLogoutRedirect, nil)
}

func handleExistingSessionOnLogout(
	r *http.Request,
	sessionIdentifier string,
	idToken *oauth.JwtToken,
	client *models.Client,
	database data.Database,
	auditLogger AuditLogger,
	authHelper AuthHelper,
) error {
	sid := idToken.GetStringClaim("sid")
	if len(sid) == 0 || sid != sessionIdentifier {
		return errors.New("Invalid session identifier in id_token_hint")
	}

	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil || userSession == nil {
		return err
	}

	err = database.UserSessionLoadClients(nil, userSession)
	if err != nil {
		return err
	}

	err = database.UserSessionClientsLoadClients(nil, userSession.Clients)
	if err != nil {
		return err
	}

	for idx, sessionClient := range userSession.Clients {
		if sessionClient.Client.ClientIdentifier == client.ClientIdentifier {
			err = database.DeleteUserSessionClient(nil, userSession.Clients[idx].Id)
			if err != nil {
				return err
			}

			auditLogger.Log(constants.AuditDeletedUserSessionClient, map[string]interface{}{
				"userId":        userSession.UserId,
				"userSessionId": userSession.Id,
				"clientId":      sessionClient.Client.Id,
				"loggedInUser":  authHelper.GetLoggedInSubject(r),
			})

			if len(userSession.Clients) == 1 {
				err = database.DeleteUserSession(nil, userSession.Id)
				if err != nil {
					return err
				}

				auditLogger.Log(constants.AuditLogout, map[string]interface{}{
					"userId":            userSession.UserId,
					"sessionIdentifier": sessionIdentifier,
					"loggedInUser":      authHelper.GetLoggedInSubject(r),
				})
			}
			break
		}
	}

	return nil
}

func HandleAccountLogoutPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// If id_token_hint is present in the POST body, handle same as GET flow
		if hint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint"); len(hint) > 0 {
			// Use a fresh token parser based on database
			tp := oauthdb.NewTokenParser(database)
			doLogoutWithIdToken(w, r, httpHelper, httpSession, authHelper, database, tp, auditLogger)
			return
		}

		sess, err := httpSession.Get(r, constants.AuthServerSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userId := int64(0)

		if len(sessionIdentifier) > 0 {
			userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if userSession != nil {
				userId = userSession.UserId
			}
		}

		// clear the session state
		sess.Values = make(map[interface{}]interface{})
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditLogout, map[string]interface{}{
			"userId":            userId,
			"sessionIdentifier": sessionIdentifier,
			"loggedInUser":      authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.GetAuthServer().BaseURL, http.StatusFound)
	}
}

// doLogoutWithIdToken contains the shared logic used by both GET and POST flows when an id_token_hint is provided.
func doLogoutWithIdToken(
	w http.ResponseWriter,
	r *http.Request,
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) {
	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

	idTokenHint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint")
	postLogoutRedirectURI := httpHelper.GetFromUrlQueryOrFormPost(r, "post_logout_redirect_uri")
	if len(postLogoutRedirectURI) == 0 {
		renderAuthError(w, r, httpHelper, i18n.NewLocalizedError(i18n.ErrCodeLogoutPostLogoutRedirectRequired, nil))
		return
	}

	clientId := httpHelper.GetFromUrlQueryOrFormPost(r, "client_id")
	// A JWE-encrypted id_token_hint must be decrypted before validation. It is
	// keyed off client_id (RP-Initiated Logout): without it we cannot know whose
	// secret derives the key. A plain signed hint is validated as-is, whether or
	// not client_id is present.
	if isEncryptedIDTokenHint(idTokenHint) {
		if len(clientId) == 0 {
			slog.Error("logout: encrypted id_token_hint requires client_id")
			renderAuthError(w, r, httpHelper, i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintDecryptFailed, nil))
			return
		}
		var locErr *i18n.LocalizedError
		idTokenHint, locErr = decryptIDTokenHint(idTokenHint, clientId, database)
		if locErr != nil {
			renderAuthError(w, r, httpHelper, locErr)
			return
		}
	}

	idToken, err := tokenParser.DecodeAndValidateTokenString(idTokenHint, nil, true)
	if err != nil {
		slog.Error("logout: id_token_hint validation failed", "err", err)
		renderAuthError(w, r, httpHelper, i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintInvalid, nil))
		return
	}

	issuer := idToken.GetStringClaim("iss")
	if len(issuer) == 0 {
		renderAuthError(w, r, httpHelper, i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintIssMissing, nil))
		return
	}
	if issuer != settings.Issuer {
		renderAuthError(w, r, httpHelper, i18n.NewLocalizedError(i18n.ErrCodeLogoutIdTokenHintIssMismatch, nil))
		return
	}

	client, locErr := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)
	if locErr != nil {
		renderAuthError(w, r, httpHelper, locErr)
		return
	}

	sessionIdentifier := ""
	if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
		sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
	}
	// Fallback: if no session cookie/context, use sid from id_token_hint
	if len(sessionIdentifier) == 0 {
		if sidClaim := idToken.GetStringClaim("sid"); len(sidClaim) > 0 {
			sessionIdentifier = sidClaim
		}
	}

	if len(sessionIdentifier) > 0 {
		err = handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}

	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	sess.Values = make(map[interface{}]interface{})
	if err = httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	state := httpHelper.GetFromUrlQueryOrFormPost(r, "state")
	sid := sessionIdentifier
	logoutUri := postLogoutRedirectURI + "?sid=" + sid
	if len(state) > 0 {
		logoutUri += "&state=" + state
	}
	http.Redirect(w, r, logoutUri, http.StatusFound)
}

// buildPostLogoutRedirect returns the Location value for a post-logout redirect: the
// registered URI with the RP's state written into its query, properly escaped. Building
// it by string concatenation instead is what let a state containing "+", "/", "=", "#"
// or "&" reach the RP altered or truncated, and let a registered URI that already
// carried a query gain a second "?" (#109).
//
// The registered query is copied field by field, verbatim and in order, empty fields
// included, and only the RP's state is encoded. Decoding it into url.Values and
// re-encoding it, which is what
// redirToClientWithError does in handler_authorize.go, does not round-trip: url.Query
// discards the error from url.ParseQuery, so a field separated by a literal semicolon
// ("?lang=en;mode=dark") is deleted outright and the caller never learns; Encode sorts
// by key, so a query whose order the RP signs over comes back reordered; a valueless
// field ("?flag") gains an "="; and percent-escapes are normalised ("%7E" to "~"). The
// registered URI is an operator-registered target that was just matched exactly, so
// altering its query sends the RP somewhere it did not register. None of those shapes is
// rejected at registration: validateRedirectURI's excluded-character set is
// "<>\"{}|\\^` " and admits a semicolon.
//
// Copying registered bytes into a Location header is safe here because url.Parse above
// rejects CR, LF and NUL outright ("net/url: invalid control character in URL"), so a
// registered URI that reaches this point cannot carry a header-splitting byte. The RP's
// state is attacker-influenced and is escaped, never copied.
//
// Three further properties, each load-bearing, so changing one back is a behaviour
// change rather than a tidy-up:
//
//   - Exactly one state reaches the RP. Every registered field whose decoded name is
//     "state" is dropped and one is appended, so the RP reads the value it sent rather
//     than the registered one, and never both with the choice left to its parser.
//   - No TrimSpace. OpenID Connect RP-Initiated Logout 1.0 section 2 calls state an
//     "Opaque value used by the RP to maintain state between the logout request and the
//     callback", so the OP has no licence to alter it. Trimming would turn a
//     whitespace-only state into no state at all.
//   - url.Parse rather than url.ParseRequestURI. A fragment is not part of an HTTP
//     request URI, so ParseRequestURI keeps a literal "#" in the path and the result
//     comes back as ".../out%23frag?state=abc". url.Parse still rejects the genuinely
//     malformed, so the looser parse gives up nothing.
//
// statePresent, rather than a len(state) > 0 guard, is what keeps three cases distinct:
// a state that was absent writes nothing, a state supplied empty comes back as "state=",
// and a whitespace-only state survives byte-identical.
func buildPostLogoutRedirect(registeredURI string, state string, statePresent bool) (string, error) {
	redirUrl, err := url.Parse(registeredURI)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse post-logout redirect URI")
	}

	if !statePresent {
		return redirUrl.String(), nil
	}

	fields := make([]string, 0, 4)
	// An empty RawQuery is the only field the loop must not see. strings.Split("", "&")
	// yields one empty string rather than nothing, so iterating unconditionally would
	// append a leading "&" to a URI that had no query at all. Guarding here rather than
	// skipping empty fields inside the loop is what keeps the empty fields a registered
	// query really did carry: "?a=1&&b=2" stays that way instead of collapsing to
	// "?a=1&b=2", which is a different target from the one the operator registered and
	// the OP just matched exactly (#109).
	if redirUrl.RawQuery != "" {
		for _, field := range strings.Split(redirUrl.RawQuery, "&") {
			name := field
			if i := strings.IndexByte(field, '='); i >= 0 {
				name = field[:i]
			}
			// An unescapable name cannot be "state", and is kept as it stands rather than
			// dropped, since the point is to preserve what was registered.
			if decoded, err := url.QueryUnescape(name); err == nil && decoded == "state" {
				continue
			}
			fields = append(fields, field)
		}
	}
	fields = append(fields, "state="+url.QueryEscape(state))

	redirUrl.RawQuery = strings.Join(fields, "&")
	return redirUrl.String(), nil
}
