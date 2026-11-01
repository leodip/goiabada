package clientauth_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// The client authentication limit as client authentication spends it (#707 decisions 3, 4 and 10):
// which secret checks reserve, which charge and which refund, through a limiter port faked here.

// secretCheck is what the fake limiter saw of one check: the client it reserved for, and the
// verdict it was released with, nil while it is unreleased.
type secretCheck struct {
	client   string
	released *bool
}

// fakeSecretCheckLimiter records every reservation and its release, and refuses or faults when told
// to. It implements clientauth.SecretCheckLimiter directly, as the rate limiter does.
type fakeSecretCheckLimiter struct {
	mu     sync.Mutex
	checks []*secretCheck
	// refuse and fault, when set, are what every reservation answers.
	refuse *clientauth.LimitReachedError
	fault  error
}

func (f *fakeSecretCheckLimiter) ReserveSecretCheck(_ context.Context, clientIdentifier string) (clientauth.SecretCheckReservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, &secretCheck{client: clientIdentifier})
	if f.refuse != nil {
		return nil, f.refuse
	}
	if f.fault != nil {
		return nil, f.fault
	}
	return &fakeReservation{limiter: f, check: f.checks[len(f.checks)-1]}, nil
}

type fakeReservation struct {
	limiter *fakeSecretCheckLimiter
	check   *secretCheck
}

func (r *fakeReservation) Release(_ context.Context, failed bool) {
	r.limiter.mu.Lock()
	defer r.limiter.mu.Unlock()
	if r.check.released != nil {
		panic("a reservation was released twice")
	}
	r.check.released = &failed
}

// seen answers each check as "client:charged", "client:refunded" or "client:held".
func (f *fakeSecretCheckLimiter) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.checks {
		switch {
		case c.released == nil:
			out = append(out, c.client+":held")
		case *c.released:
			out = append(out, c.client+":charged")
		default:
			out = append(out, c.client+":refunded")
		}
	}
	return out
}

func adminConsoleClient(t *testing.T) *record.Client {
	t.Helper()
	client := confidentialClient(t)
	client.ClientIdentifier = "admin-console-client"
	return client
}

// TestVerifySecret_TheLimitCountsFailedSecretChecksOfAConfidentialClient: a confidential client's
// check reserves before the comparison and is released at once, charged for a missing or wrong
// secret and refunded for the right one; a public client's compares no secret and reserves nothing,
// and neither does the admin console's client, whichever secret it sends.
func TestVerifySecret_TheLimitCountsFailedSecretChecksOfAConfidentialClient(t *testing.T) {
	rows := []struct {
		name   string
		client func(t *testing.T) *record.Client
		secret string
		want   *refusal
		seen   []string
	}{
		{"a confidential client with no secret", confidentialClient, "", &secretRequired, []string{"the_client:charged"}},
		{"a confidential client with a wrong secret", confidentialClient, "not_the_secret", &wrongSecret, []string{"the_client:charged"}},
		{"a confidential client with its secret", confidentialClient, theSecret, nil, []string{"the_client:refunded"}},
		{"a public client with a secret", func(*testing.T) *record.Client { return publicClient() }, "any_secret", &superfluousSecret, nil},
		{"a public client with no secret", func(*testing.T) *record.Client { return publicClient() }, "", nil, nil},
		{"the admin console's client with a wrong secret", adminConsoleClient, "not_the_secret", &wrongSecret, nil},
		{"the admin console's client with no secret", adminConsoleClient, "", &secretRequired, nil},
		{"the admin console's client with its secret", adminConsoleClient, theSecret, nil, nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			limiter := &fakeSecretCheckLimiter{}
			err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), testDataCipher, limiter).
				VerifySecret(context.Background(), row.client(t), row.secret)

			if row.want == nil {
				require.NoError(t, err)
			} else {
				refusedWith(t, err, *row.want)
			}
			assert.Equal(t, row.seen, limiter.seen())
		})
	}
}

// TestVerifySecret_AClientOverItsLimitIsRefusedBeforeTheComparison: the limiter's refusal comes back
// as it was given, not as an invalid_client, and no secret is compared, the right one included. The
// stored secret here cannot be opened with the cipher, so a comparison would have been a fault.
func TestVerifySecret_AClientOverItsLimitIsRefusedBeforeTheComparison(t *testing.T) {
	for _, secret := range []string{theSecret, "not_the_secret", ""} {
		t.Run("secret "+secret, func(t *testing.T) {
			refused := &clientauth.LimitReachedError{RetryAfter: time.Hour}
			limiter := &fakeSecretCheckLimiter{refuse: refused}
			otherCipher := newCipher(t, "fedcba9876543210fedcba9876543210")

			err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), otherCipher, limiter).
				VerifySecret(context.Background(), confidentialClient(t), secret)

			var limitReached *clientauth.LimitReachedError
			require.ErrorAs(t, err, &limitReached)
			assert.Same(t, refused, limitReached)
			assert.Equal(t, 3600*time.Second, limitReached.RetryAfter)
			var detail *oauth.ErrorDetail
			assert.NotErrorAs(t, err, &detail, "the credentials were never judged, so it is no error response")
			assert.Equal(t, []string{"the_client:held"}, limiter.seen(), "a refusal holds no reservation to release")
		})
	}
}

// TestVerifySecret_ACountThatCannotBeReadIsAFault: the endpoint answers a fault, so the error is
// neither a refusal nor a limit, it carries the cause, and no secret is compared.
func TestVerifySecret_ACountThatCannotBeReadIsAFault(t *testing.T) {
	cause := errors.New("the counter table is unreachable")
	limiter := &fakeSecretCheckLimiter{fault: cause}
	otherCipher := newCipher(t, "fedcba9876543210fedcba9876543210")

	err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), otherCipher, limiter).
		VerifySecret(context.Background(), confidentialClient(t), theSecret)

	require.ErrorIs(t, err, cause)
	var detail *oauth.ErrorDetail
	assert.NotErrorAs(t, err, &detail)
	var limitReached *clientauth.LimitReachedError
	assert.NotErrorAs(t, err, &limitReached)
	assert.Equal(t, []string{"the_client:held"}, limiter.seen())
}

// TestVerifySecret_ASecretThatCannotBeOpenedIsRefunded: a stored secret the cipher cannot open is a
// fault that judged nothing about the client, so its reservation is handed back uncharged.
func TestVerifySecret_ASecretThatCannotBeOpenedIsRefunded(t *testing.T) {
	limiter := &fakeSecretCheckLimiter{}
	otherCipher := newCipher(t, "fedcba9876543210fedcba9876543210")

	err := clientauth.NewAuthenticator(datamocks.NewDatabase(t), otherCipher, limiter).
		VerifySecret(context.Background(), confidentialClient(t), theSecret)

	require.Error(t, err)
	var detail *oauth.ErrorDetail
	assert.NotErrorAs(t, err, &detail)
	assert.Equal(t, []string{"the_client:refunded"}, limiter.seen())
}

// TestAuthenticate_OnlyAFoundEnabledConfidentialClientReserves: a request with no identifier, an
// unknown client and a disabled one are refused before any secret is looked at, so they spend
// nothing, whatever secret they sent; and the identifier reserved for is the stored client's.
func TestAuthenticate_OnlyAFoundEnabledConfidentialClientReserves(t *testing.T) {
	rows := []struct {
		name       string
		identifier string
		stored     func(t *testing.T) *record.Client
		secret     string
		status     int
		seen       []string
	}{
		{"no client identifier", "", nil, "not_the_secret", http.StatusBadRequest, nil},
		{"an unknown client", "the_client", func(*testing.T) *record.Client { return nil }, "not_the_secret", http.StatusUnauthorized, nil},
		{"a disabled client", "the_client", func(t *testing.T) *record.Client {
			client := confidentialClient(t)
			client.Enabled = false
			return client
		}, "not_the_secret", http.StatusUnauthorized, nil},
		{"an enabled confidential client", "the_client", confidentialClient, "not_the_secret", http.StatusUnauthorized,
			[]string{"the_client:charged"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			if row.stored != nil {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, row.identifier).
					Return(row.stored(t), nil).Once()
			}
			limiter := &fakeSecretCheckLimiter{}

			_, err := clientauth.NewAuthenticator(database, testDataCipher, limiter).
				Authenticate(context.Background(), row.identifier, row.secret)

			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, row.status, detail.HTTPStatus())
			assert.Equal(t, row.seen, limiter.seen())
		})
	}
}

// TestAuthenticateConfidential_APublicClientReservesNothing: refused as a client that cannot
// authenticate before its secret is looked at, so it compares none and spends nothing.
func TestAuthenticateConfidential_APublicClientReservesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").
		Return(publicClient(), nil).Once()
	limiter := &fakeSecretCheckLimiter{}

	_, err := clientauth.NewAuthenticator(database, testDataCipher, limiter).
		AuthenticateConfidential(context.Background(), "the_client", "any_secret")

	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_client", detail.Code())
	assert.Empty(t, limiter.seen())
}
