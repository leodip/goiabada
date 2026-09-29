package protocolvalidation

import (
	"crypto/subtle"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/customerrors"
)

const clientSecretRequiredErrorMsg = "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

// One message for a superfluous secret, so the grants that refuse one cannot drift into several
// spellings of one fact (#245).
const clientSecretNotRequiredErrorMsg = "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request."

// The two answers a wrong secret gets today: the authorization code and refresh token grants give
// the first, client credentials and password the second. Each grant passes its own to
// authenticateClient, so moving the check into one function changed no answer (#437).
const (
	wrongClientSecretErrorMsg      = "Client authentication failed. Please review your client_secret."
	wrongClientSecretShortErrorMsg = "Client authentication failed."
)

// authenticateClient is the one client authentication at the token endpoint: every grant calls
// it at the point in its own order where it authenticates the client (#437).
//
// A confidential client must present its secret (RFC 6749 section 3.2.1); a missing or wrong one
// is invalid_client, 401, with a Basic challenge when the client tried the Authorization header,
// as RFC 6749 section 5.2 requires. The comparison is constant-time.
//
// A public client that presents a secret is refused invalid_request. That is symmetry, not a
// defect fix (#245 decision 11): no specification requires refusing a superfluous secret and
// nothing was exposed by ignoring one; what it buys is that one request gets one answer whichever
// grant carries it. The client credentials grant never reaches that branch, because it refuses a
// public client before authenticating.
func (val *TokenValidator) authenticateClient(client *models.Client, presentedSecret string,
	usedBasicAuth bool, wrongSecretErrorMsg string) error {
	if client.IsPublic {
		if len(presentedSecret) > 0 {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				clientSecretNotRequiredErrorMsg, http.StatusBadRequest)
		}
		return nil
	}

	if len(presentedSecret) == 0 {
		return invalidClientError(usedBasicAuth, clientSecretRequiredErrorMsg)
	}

	clientSecret, err := val.dataCipher.Decrypt(client.ClientSecretEncrypted)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(presentedSecret)) != 1 {
		return invalidClientError(usedBasicAuth, wrongSecretErrorMsg)
	}
	return nil
}

// invalidClientError is RFC 6749 section 5.2's invalid_client: 401, and a Basic challenge when
// the client attempted to authenticate through the Authorization header.
func invalidClientError(usedBasicAuth bool, description string) *customerrors.ErrorDetail {
	if usedBasicAuth {
		return NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
			description, http.StatusUnauthorized, "Basic")
	}
	return customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
		description, http.StatusUnauthorized)
}
