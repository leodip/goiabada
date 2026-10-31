package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"net/url"

	"github.com/golang-jwt/jwt/v5"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/loopback"
)

// accountLogoutDatabase is what the account logout endpoint needs: the client whose sign-out
// redirect URIs hold the target, the session being ended, the clients it authorized, and the key
// that signs the logout token.
type accountLogoutDatabase interface {
	ClientLoadPostLogoutRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetClientsByPostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, uri string) ([]record.Client, error)
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	UserSessionClientsLoadClients(ctx context.Context, tx *sql.Tx, userSessionClients []record.UserSessionClient) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// HandleAccountLogoutRequestPost - POST /api/v1/account/logout-request
// Returns a prepared logout instruction: a self-submitting form's parameters when the request asks
// for api.AccountLogoutResponseModeFormPost, and a ready-to-follow redirect URL otherwise.
func HandleAccountLogoutRequestPost(
	database accountLogoutDatabase,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtToken, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		// Parse request
		var req api.AccountLogoutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		postLogout := req.PostLogoutRedirectUri
		if postLogout == "" {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutRedirectURIRequired, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// The two rules /auth/logout applies to a target before it redirects, so this endpoint never
		// hands out a sign-out URL that cannot take the user back. Both run before the client is
		// resolved, as /auth/authorize tests a URI before loading anything: an unusable value costs
		// no query, and resolving by URI would otherwise answer it "client unresolved" rather than
		// naming what is wrong with it. The absolute-URI rule comes first because a hostless http
		// URI fails it and is named for that (#590 decision 13).
		if !urlmatch.IsAbsoluteRedirectURI(postLogout) {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutRedirectURINotAbsolute, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if loopback.IsPlainHTTPOff(postLogout) {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutRedirectURIInsecureHTTP, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// Resolve the client, and check the target is one of its sign-out redirect URIs: a sign-out
		// returns only to an address on that list, matched exactly, never to one of the client's
		// redirect URIs (#147 decision 1).
		var client *record.Client
		var err error
		if req.ClientIdentifier != "" {
			// A failed lookup is the server's fault and a missing row the caller's, so the two
			// answer apart: 500 and 400. Folding them answered a database outage as a bad client
			// identifier, which a caller would fix by changing a value that was right (#425).
			client, err = database.GetClientByClientIdentifier(r.Context(), nil, req.ClientIdentifier)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "unable to load the client by its identifier"),
					"client_identifier", logging.FieldForLog(req.ClientIdentifier))
				return
			}
			if client == nil {
				writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutClientIdentifierInvalid, nil), "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			if err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "unable to load the client's sign-out redirect URIs"))
				return
			}
			found := false
			for _, uri := range client.PostLogoutRedirectURIs {
				if uri.URI == postLogout {
					found = true
					break
				}
			}
			if !found {
				writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutRedirectURINotRegistered, nil), "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		} else {
			// One query finds the clients whose sign-out redirect URIs hold the target, matched
			// exactly, and exactly one of them is the client; none or several asks the caller to
			// name it. It replaced a read of every client's list, one query per client (#147
			// decision 10, #148). The match is the lookup itself, so the client's list needs no
			// second read here.
			matches, lookupErr := database.GetClientsByPostLogoutRedirectURI(r.Context(), nil, postLogout)
			if lookupErr != nil {
				writeInternalServerError(w, r, errs.Wrap(lookupErr, "unable to find the clients holding a sign-out redirect URI"))
				return
			}
			if len(matches) != 1 {
				writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAccountLogoutClientUnresolved, nil), "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			client = &matches[0]
		}

		// Strict session check: current sid must belong to a live session and be associated with this client
		sid := jwtToken.StringClaim("sid")
		if sid == "" {
			writeJSONError(w, "Current token lacks session identifier", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}
		userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sid)
		if err != nil {
			// A failed lookup is not a missing session: 401 would tell the caller to
			// re-authenticate over what is a server fault (#425).
			writeInternalServerError(w, r, errs.Wrap(err, "unable to load the user session"))
			return
		}
		if userSession == nil {
			writeJSONError(w, "Session not found", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}
		if err = database.UserSessionLoadClients(r.Context(), nil, userSession); err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if err = database.UserSessionClientsLoadClients(r.Context(), nil, userSession.Clients); err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		hasClient := false
		for _, sc := range userSession.Clients {
			if sc.Client.Id == client.Id {
				hasClient = true
				break
			}
		}
		if !hasClient {
			writeJSONError(w, "Client not part of the current session", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}

		// Build a short-lived ID Token (id_token_hint)
		privKeyPair, err := database.GetCurrentSigningKey(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		privKey, err := signingkeys.ParsePrivateKey(dataCipher, privKeyPair)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		now := time.Now().UTC()
		claims := jwt.MapClaims{}
		claims["iss"] = settings.Issuer
		claims["sub"] = subject
		claims["iat"] = now.Unix()
		claims["sid"] = sid
		claims["aud"] = client.ClientIdentifier
		// short TTL for logout hint
		claims["exp"] = now.Add(60 * time.Second).Unix()

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = privKeyPair.KeyIdentifier
		idToken, err := token.SignedString(privKey)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Both response modes carry the same parameters to the same endpoint, and the only
		// difference is how the browser gets them there. state is present in neither when the
		// request sent none: /auth/logout distinguishes an absent state from an empty one, and
		// answers a different redirect for each, so a mode that sent "state=" where the other
		// sent nothing would log the user out to a different place (RP-Initiated Logout 1.0
		// section 2, where state is OPTIONAL; #350 decision 2).
		if req.ResponseMode == api.AccountLogoutResponseModeFormPost {
			// The form binding keeps the id_token_hint out of a top-level navigation's URL,
			// and so out of the address bar, the browser history and the Referer of anything
			// the landing page loads. Referrer-Policy and the 60-second exp do not reach an
			// intermediary proxy's access log, which is what this mode is for (#109, #350).
			params := map[string]string{
				"id_token_hint":            idToken,
				"post_logout_redirect_uri": postLogout,
			}
			if req.State != "" {
				params["state"] = req.State
			}
			writeJSON(w, r, http.StatusOK, api.AccountLogoutFormPostResponse{
				Method:   http.MethodPost,
				Endpoint: baseURL + "/auth/logout",
				Params:   params,
			})
			return
		}

		// Build logout redirect URL
		logoutUrl := fmt.Sprintf("%s/auth/logout?id_token_hint=%s&post_logout_redirect_uri=%s", baseURL, url.QueryEscape(idToken), url.QueryEscape(postLogout))
		if req.State != "" {
			logoutUrl += "&state=" + url.QueryEscape(req.State)
		}
		resp := api.AccountLogoutRedirectResponse{LogoutUrl: logoutUrl}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
