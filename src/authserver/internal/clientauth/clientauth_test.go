package clientauth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

const theSecret = "the_client_secret"

// refusal is an answer as the wire carries it: RFC 6749 section 5.2's code and description, the
// status, and the WWW-Authenticate challenge, empty for none.
type refusal struct {
	code        string
	description string
	status      int
	challenge   string
}

// The refusals as the token endpoint answered them before this package existed, written out so a
// change of wording or shape fails here.
var (
	missingClientId = refusal{"invalid_request", "Missing required client_id parameter.",
		http.StatusBadRequest, ""}
	unknownClient = refusal{"invalid_client", "Client does not exist.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	disabledClient = refusal{"invalid_client", "Client is disabled.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	secretRequired = refusal{"invalid_client", "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	wrongSecret = refusal{"invalid_client", "Client authentication failed. Please review your client_secret.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	// A public client that sends a secret has not failed to authenticate, so no challenge.
	superfluousSecret = refusal{"invalid_request", "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.",
		http.StatusBadRequest, ""}
)

func refusedWith(t *testing.T, err error, want refusal) {
	t.Helper()
	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, want.code, detail.Code())
	assert.Equal(t, want.description, detail.Description())
	assert.Equal(t, want.status, detail.HTTPStatus())
	assert.Equal(t, want.challenge, detail.WWWAuthenticate())
}

func newCipher(t *testing.T, key string) *encryption.DataCipher {
	t.Helper()
	dataCipher, err := encryption.NewDataCipher([]byte(key))
	require.NoError(t, err)
	return dataCipher
}

var testDataCipher = func() *encryption.DataCipher {
	dataCipher, err := encryption.NewDataCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	return dataCipher
}()

func confidentialClient(t *testing.T) *record.Client {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt(theSecret)
	require.NoError(t, err)
	return &record.Client{Id: 7, ClientIdentifier: "the_client", Enabled: true, ClientSecretEncrypted: encrypted}
}

func publicClient() *record.Client {
	return &record.Client{Id: 8, ClientIdentifier: "the_client", Enabled: true, IsPublic: true}
}

func TestFindClient(t *testing.T) {
	t.Run("a missing client identifier is refused before any lookup", func(t *testing.T) {
		// No expectation is set, so a lookup fails the test.
		authenticator := clientauth.NewAuthenticator(datamocks.NewDatabase(t), testDataCipher)

		client, err := authenticator.FindClient(context.Background(), "")

		assert.Nil(t, client)
		refusedWith(t, err, missingClientId)
	})

	rows := []struct {
		name   string
		stored *record.Client
		want   refusal
	}{
		{"an unknown client", nil, unknownClient},
		{"a disabled confidential client", &record.Client{ClientIdentifier: "the_client"}, disabledClient},
		{"a disabled public client", &record.Client{ClientIdentifier: "the_client", IsPublic: true}, disabledClient},
	}
	for _, row := range rows {
		t.Run(row.name+" is refused", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").
				Return(row.stored, nil).Once()

			client, err := clientauth.NewAuthenticator(database, testDataCipher).
				FindClient(context.Background(), "the_client")

			assert.Nil(t, client)
			refusedWith(t, err, row.want)
		})
	}

	t.Run("an enabled client is found, whatever its secret", func(t *testing.T) {
		stored := confidentialClient(t)
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").
			Return(stored, nil).Once()

		client, err := clientauth.NewAuthenticator(database, testDataCipher).
			FindClient(context.Background(), "the_client")

		require.NoError(t, err)
		assert.Same(t, stored, client)
	})

	t.Run("a fault reading the client is returned, not answered as a refusal", func(t *testing.T) {
		fault := errors.New("the database is down")
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").
			Return(nil, fault).Once()

		client, err := clientauth.NewAuthenticator(database, testDataCipher).
			FindClient(context.Background(), "the_client")

		assert.Nil(t, client)
		require.ErrorIs(t, err, fault)
		var detail *oauth.ErrorDetail
		assert.NotErrorAs(t, err, &detail, "a fault is not an error response")
	})
}

func TestVerifySecret(t *testing.T) {
	rows := []struct {
		name   string
		public bool
		secret string
		// want is the refusal; nil means the client is authenticated.
		want *refusal
	}{
		{"confidential, no secret", false, "", &secretRequired},
		{"confidential, wrong secret", false, "not_the_secret", &wrongSecret},
		// One byte short and one byte over: the comparison is of the whole value.
		{"confidential, secret missing its last byte", false, theSecret[:len(theSecret)-1], &wrongSecret},
		{"confidential, secret with a byte appended", false, theSecret + "x", &wrongSecret},
		{"confidential, right secret", false, theSecret, nil},
		{"public, superfluous secret", true, "any_secret", &superfluousSecret},
		{"public, no secret", true, "", nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			client := confidentialClient(t)
			if row.public {
				client = publicClient()
			}
			// No expectation is set: checking a secret reads nothing.
			err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), testDataCipher).
				VerifySecret(client, row.secret)

			if row.want == nil {
				assert.NoError(t, err)
				return
			}
			refusedWith(t, err, *row.want)
		})
	}

	t.Run("a secret that cannot be decrypted is a fault, not a refusal", func(t *testing.T) {
		otherCipher := newCipher(t, "fedcba9876543210fedcba9876543210")
		err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), otherCipher).
			VerifySecret(confidentialClient(t), theSecret)

		require.Error(t, err)
		var detail *oauth.ErrorDetail
		assert.NotErrorAs(t, err, &detail, "a fault is not an error response")
	})
}

// TestAuthenticate is the one call an endpoint makes when nothing of its own sits between finding
// the client and checking its secret: the client is found, refused if unknown or disabled, and only
// then its secret checked.
func TestAuthenticate(t *testing.T) {
	rows := []struct {
		name       string
		identifier string
		stored     func(t *testing.T) *record.Client
		secret     string
		want       *refusal
	}{
		{"no client identifier", "", nil, theSecret, &missingClientId},
		{"an unknown client", "the_client", func(*testing.T) *record.Client { return nil }, theSecret, &unknownClient},
		// The right secret does not get a disabled client in.
		{"a disabled client with its right secret", "the_client", func(t *testing.T) *record.Client {
			client := confidentialClient(t)
			client.Enabled = false
			return client
		}, theSecret, &disabledClient},
		{"a confidential client with no secret", "the_client", confidentialClient, "", &secretRequired},
		{"a confidential client with a wrong secret", "the_client", confidentialClient, "not_the_secret", &wrongSecret},
		{"a confidential client with its secret", "the_client", confidentialClient, theSecret, nil},
		{"a public client with a secret", "the_client", func(*testing.T) *record.Client { return publicClient() }, "any_secret", &superfluousSecret},
		{"a public client by its identifier alone", "the_client", func(*testing.T) *record.Client { return publicClient() }, "", nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			var stored *record.Client
			if row.stored != nil {
				stored = row.stored(t)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, row.identifier).
					Return(stored, nil).Once()
			}

			client, err := clientauth.NewAuthenticator(database, testDataCipher).
				Authenticate(context.Background(), row.identifier, row.secret)

			if row.want == nil {
				require.NoError(t, err)
				assert.Same(t, stored, client)
				return
			}
			assert.Nil(t, client)
			refusedWith(t, err, *row.want)
		})
	}
}
