package integrationtests

import (
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// createClientForClientIdComparison registers a client whose identifier is entirely lowercase, so
// that an upper-cased spelling of it is a different string on every engine rather than a different
// string on some of them. Created through the data layer, the way token_general_test.go already
// does, because what is under test is how the token endpoint compares the identifier and not how
// it was stored.
func createClientForClientIdComparison(t *testing.T) *models.Client {
	t.Helper()

	client := &models.Client{
		ClientIdentifier:         strings.ToLower("test-client-" + gofakeit.LetterN(8)),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	assert.Nil(t, err)
	return client
}

// assertClientIdResolves is the control every case below runs first, and it is what stops the
// refusal that follows passing because the client was never created. With the identifier spelled
// exactly as registered the endpoint gets PAST the client lookup and refuses the grant type
// instead, which is only reachable once a client has been found.
func assertClientIdResolves(t *testing.T, destUrl, clientIdentifier string) {
	t.Helper()

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type": {"invalid_grant_type"},
		"client_id":  {clientIdentifier},
	})
	assert.Equal(t, "unsupported_grant_type", data["error"],
		"the exact identifier must get past the client lookup, or the refusals below prove nothing")
}

// TestToken_ClientIdCaseVariantIsRefused is RFC 6749 section 1.9 at the boundary a client actually
// meets: "Unless otherwise noted, all the protocol parameter names and values are case sensitive",
// and section 2.2 notes no exception for client_id. A request naming the client in a case it was
// not registered in therefore names no client.
//
// SQLite and PostgreSQL have always answered this way, their `=` being exact. MySQL and SQL Server
// answered the other way until migration 000040 moved every string column to a case-sensitive
// collation, so on those two engines this case is the conformance fix itself being observed, and
// their result is the check suite's rather than the local sqlite run's (#283).
func TestToken_ClientIdCaseVariantIsRefused(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	client := createClientForClientIdComparison(t)

	assertClientIdResolves(t, destUrl, client.ClientIdentifier)

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type": {"invalid_grant_type"},
		"client_id":  {strings.ToUpper(client.ClientIdentifier)},
	})
	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

// TestToken_ClientIdTrailingSpaceIsRefused is the same property against a fold no collation turns
// off. SQL Server pads both operands of `=` to equal length, under every collation it has including
// BIN and BIN2, while DATALENGTH shows the strings differ; so client_id=myapp with a trailing space
// resolved the client registered as myapp there both before #283 and after the collation change,
// and resolves nothing on the other three engines.
//
// What closes it is above the collation, because no collation can: GetClientByClientIdentifier
// compares the identifier it got back against the one it was asked for and returns nothing when the
// engine folded the two together. Nothing on the request path trims first, either:
// ValidateTokenRequest checks only that client_id is non-empty before handing the value to the
// lookup, and ValidateIdentifier runs at registration, never on a lookup.
//
// SQL Server is the only engine on which this case could fail, so its result is the check suite's.
// Here it holds because SQLite compares the bytes.
func TestToken_ClientIdTrailingSpaceIsRefused(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	client := createClientForClientIdComparison(t)

	assertClientIdResolves(t, destUrl, client.ClientIdentifier)

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type": {"invalid_grant_type"},
		"client_id":  {client.ClientIdentifier + " "},
	})
	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}
