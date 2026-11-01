// Package clientauth authenticates the client calling an endpoint, RFC 6749 section 2.3, from the
// plain values its request presented: the client identifier and the secret, however they arrived.
// It owns the refusals and their wording, so every endpoint that authenticates a client answers a
// failure the one way. Reading the credentials off a request, and logging a refusal, are the
// handlers' (#676 decision 9).
//
// Authenticate is the whole of it, and AuthenticateConfidential for an endpoint a public client may
// not call. The token validator calls its two halves apart instead,
// FindClient before it looks at the grant and VerifySecret at the point in each grant's own order
// where that grant authenticates the client, so its answers and their order stay what they were
// (#437).
package clientauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// ChallengeRealm is the realm of every challenge this server writes, the Basic challenge below and
// the Bearer challenge of /userinfo and the admin and account APIs, which middleware.BearerRealm
// names. RFC 7617 section 2 makes the realm REQUIRED on a Basic challenge, RFC 6750 section 3 wants
// an auth-param on every Bearer one, and RFC 9110 section 11.5 defines a protection space as the
// origin plus the realm, so one value keeps this server one protection space. It is declared here,
// in the lowest package that writes a challenge: protocolvalidation imports this package and
// middleware imports both, never the reverse (#435, #437).
const ChallengeRealm = "goiabada"

// BasicChallenge is the WWW-Authenticate value on every invalid_client, whether the client sent
// its credentials in the Authorization header or in the form body. RFC 9110 section 15.5.2 requires
// a challenge on every 401, and RFC 7617 section 2 a quoted realm on a Basic one; before #437 only a
// failed Basic attempt got one, and a bare "Basic" at that.
const BasicChallenge = `Basic realm="` + ChallengeRealm + `"`

const clientSecretRequiredErrorMsg = "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

// One message for a superfluous secret, so the grants that refuse one cannot drift into several
// spellings of one fact (#245).
const clientSecretNotRequiredErrorMsg = "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request."

// The one answer a wrong secret gets, whichever grant carried it. Client credentials and password
// answered a shorter text until #437, so the same failure read two ways depending on the grant.
const wrongClientSecretErrorMsg = "Client authentication failed. Please review your client_secret."

// AuthenticateConfidential's refusal of a public client.
const publicClientCannotIntrospectErrorMsg = "This client is configured as public, and a public client cannot introspect tokens. Introspect as a confidential client."

// UnreadableBasicCredentials' description.
const unreadableBasicCredentialsErrorMsg = "Client authentication failed: the Basic credentials in the Authorization header could not be read."

// FindClient's refusals.
const (
	clientIdMissingErrorMsg    = "Missing required client_id parameter."
	clientDoesNotExistErrorMsg = "Client does not exist."
	clientDisabledErrorMsg     = "Client is disabled."
)

// Database is what client authentication reads: the client the request names.
type Database interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
}

// Authenticator authenticates clients against the stored clients, opening their secrets with the
// process's data cipher.
type Authenticator struct {
	database   Database
	dataCipher *encryption.DataCipher
}

func NewAuthenticator(database Database, dataCipher *encryption.DataCipher) *Authenticator {
	return &Authenticator{database: database, dataCipher: dataCipher}
}

// Authenticate returns the client clientIdentifier names once presentedSecret authenticates it, or
// the refusal: FindClient's, then VerifySecret's. A public client is authenticated by its
// identifier alone. A refusal is an *oauth.ErrorDetail; any other error is a fault, the database's
// or the cipher's, and says nothing about the client.
func (a *Authenticator) Authenticate(ctx context.Context, clientIdentifier, presentedSecret string) (*record.Client, error) {
	client, err := a.FindClient(ctx, clientIdentifier)
	if err != nil {
		return nil, err
	}
	if err := a.VerifySecret(client, presentedSecret); err != nil {
		return nil, err
	}
	return client, nil
}

// AuthenticateConfidential is Authenticate for an endpoint whose callers MUST authenticate, the
// introspection endpoint (RFC 7662 section 4, #676 decision 9). A public client holds nothing to
// authenticate with, so it is refused as a client that failed to authenticate, invalid_client, before
// its secret is looked at: whether it sent one or not, it gets the one answer.
func (a *Authenticator) AuthenticateConfidential(ctx context.Context, clientIdentifier, presentedSecret string) (*record.Client, error) {
	client, err := a.FindClient(ctx, clientIdentifier)
	if err != nil {
		return nil, err
	}
	if client.IsPublic {
		return nil, invalidClientError(publicClientCannotIntrospectErrorMsg)
	}
	if err := a.VerifySecret(client, presentedSecret); err != nil {
		return nil, err
	}
	return client, nil
}

// FindClient returns the enabled client clientIdentifier names. A missing identifier is
// invalid_request, 400, with no challenge: no client was named, so none failed to authenticate
// (#437 decision 9). An unknown client and a disabled one are failed client authentications, RFC
// 6749 section 5.2's invalid_client, whose own example is the unknown client: until #437 they
// answered invalid_request and invalid_grant at 400. The descriptions are unchanged.
func (a *Authenticator) FindClient(ctx context.Context, clientIdentifier string) (*record.Client, error) {
	if len(clientIdentifier) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			clientIdMissingErrorMsg, http.StatusBadRequest)
	}

	client, err := a.database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, invalidClientError(clientDoesNotExistErrorMsg)
	}
	if !client.Enabled {
		return nil, invalidClientError(clientDisabledErrorMsg)
	}
	return client, nil
}

// VerifySecret checks the secret a request presented for client, which FindClient found.
//
// A confidential client must present its secret (RFC 6749 section 3.2.1); a missing or wrong one
// is invalid_client. The comparison is constant-time.
//
// A public client that presents a secret is refused invalid_request. That is symmetry, not a
// defect fix (#245 decision 11): no specification requires refusing a superfluous secret and
// nothing was exposed by ignoring one; what it buys is that one request gets one answer whichever
// grant carries it. The client credentials grant never reaches that branch, because it refuses a
// public client before authenticating.
func (a *Authenticator) VerifySecret(client *record.Client, presentedSecret string) error {
	if client.IsPublic {
		if len(presentedSecret) > 0 {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				clientSecretNotRequiredErrorMsg, http.StatusBadRequest)
		}
		return nil
	}

	if len(presentedSecret) == 0 {
		return invalidClientError(clientSecretRequiredErrorMsg)
	}

	clientSecret, err := a.dataCipher.Decrypt(client.ClientSecretEncrypted)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(presentedSecret)) != 1 {
		return invalidClientError(wrongClientSecretErrorMsg)
	}
	return nil
}

// UnreadableBasicCredentials is the refusal of a request whose Authorization header names the Basic
// scheme but whose credentials cannot be read: none, not base64, or no colon once decoded. The client
// tried the header, so RFC 6749 section 5.2 requires the 401 with the challenge of the scheme it used,
// and the body is not read in its place (#707 decision 12). No client was identified.
func UnreadableBasicCredentials() *oauth.ErrorDetail {
	return invalidClientError(unreadableBasicCredentialsErrorMsg)
}

// invalidClientError is every invalid_client: an unknown client, a disabled one, a missing or
// wrong secret, and unreadable Basic credentials. Always 401 with BasicChallenge, whether the client
// used the Authorization header or the form body (#437).
//
// RFC 6749 section 5.2 makes 401 a MAY in general and a MUST, with a challenge, only for a client
// that tried the Authorization header; RFC 9110 section 15.5.2 then requires a challenge on every
// 401. Answering every invalid_client the one way satisfies both and gives a client one shape to
// handle. What it costs: a browser app calling the token endpoint with a mistyped or disabled
// client_id gets a 401 with a Basic challenge, which some browsers answer with their login prompt in
// a same-origin setup.
func invalidClientError(description string) *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_client", description, http.StatusUnauthorized).
		WithWWWAuthenticate(BasicChallenge)
}
