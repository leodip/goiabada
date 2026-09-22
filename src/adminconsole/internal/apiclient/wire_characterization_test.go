package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 3, and the harness the executor moves against (#386 stage 10, round 1 finding 1).
//
// Before this file, collapsing 106 hand-written request builders onto one executor was an
// unobserved change. Measured while the reviewer raised it: 28 of the 106 methods are called from
// an apiclient test and 78 are not, and changing UpdateAccountAddress's path to /wrong-endpoint
// left all 1,465 admin console tests green. Handler tests hold ApiClient doubles and never see a
// request at all, and there is no admin console integration tier. So any method's verb, path,
// query, body, headers or success status could have moved and nothing would have said so.
//
// One row per method, landed against the unrewritten client and passing there before anything was
// collapsed, so it records what is true rather than what the rewrite produced. Each row drives
// three cases:
//
//  1. the request the method puts on the wire, and the value it decodes out of the answer;
//  2. the success status it accepts -- a different 2xx is an API error for the 95 methods written
//     that way, and is accepted by the 11 written to take the range;
//  3. a non-2xx reaching the caller as *APIError with all four of its fields intact.
//
// What a row does not pin: for the methods that send a caller-supplied request value, the expected
// body is that value marshalled, so this proves the method sends the caller's value as the whole
// body and does not prove core/api's json tags. That is user_client_test.go's job, which writes
// its bodies as literal bytes for exactly that reason. The bodies built inside a method are
// literals here, since there is no caller value to stand in for them.

const charAccessToken = "characterization-token"

// wireCase is one method's shape on the wire.
type wireCase struct {
	// name is the Go method name, and is what the coverage test counts.
	name string

	// call issues the method. ctx is carried by the methods that have taken one; the rest ignore
	// it until the stage that rewrites them. It returns the value the caller gets back, projected
	// to whatever leaf proves the decode reached the return, or nil for a method returning only
	// an error.
	call func(ctx context.Context, c *AuthServerClient) (any, error)

	verb  string
	path  string
	query string

	// Exactly one of body, bodyOf and bodyHas is set, or none for a bodiless request.
	// bodyOf is marshalled and compared; bodyHas holds substrings, for the three multipart uploads
	// whose boundary is random.
	body    string
	bodyOf  any
	bodyHas []string

	// contentType is the header the request carries; empty means the method sets none.
	// contentTypePrefix is the multipart form, whose boundary is random.
	contentType       string
	contentTypePrefix string

	// successStatus is the one status this method accepts; anySuccess2xx widens it to the range.
	successStatus int
	anySuccess2xx bool

	// reply is the body the fake auth server answers a success with, and want is what the method
	// must hand back after decoding it.
	reply string
	want  any

	// readErrorIsNotAnError marks the three methods that discard their body-read error today.
	// It is asserted by TestAuthServerClient_ThreeMethodsDiscardTheirBodyReadError, not here.
	readErrorIsNotAnError bool
}

type charRecordedRequest struct {
	verb          string
	path          string
	query         string
	body          string
	authorization string
	contentType   string
}

// charServer answers every request with status and body, recording what arrived.
func charServer(t *testing.T, status int, body string) (*AuthServerClient, *charRecordedRequest) {
	t.Helper()

	var got charRecordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.verb = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		got.authorization = r.Header.Get("Authorization")
		got.contentType = r.Header.Get("Content-Type")
		read, _ := io.ReadAll(r.Body)
		got.body = string(read)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return NewAuthServerClient(server.URL), &got
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	return string(encoded)
}

// otherSuccessStatus is a 2xx this method does not accept.
func otherSuccessStatus(accepted int) int {
	if accepted == http.StatusOK {
		return http.StatusCreated
	}
	return http.StatusOK
}

func TestAuthServerClient_EveryMethodPutsTheSameRequestOnTheWire(t *testing.T) {
	for _, tc := range wireCharacterization() {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.successStatus
			if tc.anySuccess2xx {
				status = http.StatusOK
			}
			client, got := charServer(t, status, tc.reply)

			value, err := tc.call(context.Background(), client)
			require.NoError(t, err)

			assert.Equal(t, tc.verb, got.verb, "the http verb")
			assert.Equal(t, tc.path, got.path, "the path, parameters substituted")
			assert.Equal(t, tc.query, got.query, "the query string")
			assert.Equal(t, "Bearer "+charAccessToken, got.authorization, "the bearer token")

			switch {
			case tc.contentTypePrefix != "":
				assert.True(t, strings.HasPrefix(got.contentType, tc.contentTypePrefix),
					"content type %q must start with %q", got.contentType, tc.contentTypePrefix)
			default:
				assert.Equal(t, tc.contentType, got.contentType, "the content type header")
			}

			switch {
			case len(tc.bodyHas) > 0:
				for _, fragment := range tc.bodyHas {
					assert.Contains(t, got.body, fragment, "the request body")
				}
			case tc.bodyOf != nil:
				assert.Equal(t, mustMarshal(t, tc.bodyOf), got.body, "the request body")
			default:
				assert.Equal(t, tc.body, got.body, "the request body")
			}

			if tc.want != nil {
				assert.Equal(t, tc.want, value, "the value decoded out of the answer")
			}
		})
	}
}

func TestAuthServerClient_EveryMethodAcceptsOnlyTheSuccessStatusItWasWrittenFor(t *testing.T) {
	for _, tc := range wireCharacterization() {
		t.Run(tc.name, func(t *testing.T) {
			if tc.anySuccess2xx {
				client, _ := charServer(t, http.StatusAccepted, tc.reply)
				_, err := tc.call(context.Background(), client)
				assert.NoError(t, err, "this method accepts the whole 2xx range")
				return
			}

			other := otherSuccessStatus(tc.successStatus)
			client, _ := charServer(t, other, tc.reply)

			_, err := tc.call(context.Background(), client)
			require.Error(t, err, "a 2xx this method does not accept is an error, not a decode")

			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr), "it arrives as *APIError")
			assert.Equal(t, other, apiErr.StatusCode)
		})
	}
}

func TestAuthServerClient_EveryMethodClassifiesANonSuccessThroughParseAPIError(t *testing.T) {
	const errorBody = `{"error_code":"the.error.code","error_description":"the description",` +
		`"error_args":{"name":"a value"}}`

	for _, tc := range wireCharacterization() {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := charServer(t, http.StatusUnprocessableEntity, errorBody)

			_, err := tc.call(context.Background(), client)
			require.Error(t, err)

			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr))
			assert.Equal(t, "the.error.code", apiErr.Code)
			assert.Equal(t, "the description", apiErr.Message)
			assert.Equal(t, map[string]any{"name": "a value"}, apiErr.ErrorArgs)
			assert.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)
		})
	}
}

// The table must stay whole. Reflection over ApiClient rather than a hard-coded count so a method
// added to the interface fails here rather than slipping past uncharacterized.
func TestAuthServerClient_TheCharacterizationCoversEveryApiClientMethod(t *testing.T) {
	iface := reflect.TypeOf((*ApiClient)(nil)).Elem()

	characterized := map[string]bool{}
	for _, tc := range wireCharacterization() {
		characterized[tc.name] = true
	}

	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		assert.True(t, characterized[name], "%s has no characterization row", name)
	}

	assert.Equal(t, iface.NumMethod(), len(characterized),
		"every row names a method of ApiClient and every method has a row")
}

// failingBody answers the recorded bytes and then fails, which is what a connection dropped
// mid-response looks like to io.ReadAll.
type failingBody struct {
	prefix []byte
	sent   bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		n := copy(p, b.prefix)
		return n, nil
	}
	return 0, errs.New("the connection dropped partway through the response")
}

// Round 2 finding 2. settings_keys_client.go is the only file whose methods read with
// `body, _ := io.ReadAll(resp.Body)`, and the three do not behave alike. A shared executor that
// owns bounded reading returns that error by default, which would turn a signing key rotation the
// auth server completed into a 500 the administrator may retry -- rotating twice because the reply
// was truncated. Section 2 sealed "nothing observable moves", so each outcome is recorded here and
// preserved rather than normalized.
//
// The overrun is unaffected and stays a hard failure on all three: it is decided by byte count,
// not by a read error.
func TestAuthServerClient_ThreeMethodsDiscardTheirBodyReadError(t *testing.T) {
	// The set is closed. A fourth method given the flag without a case here, or one of these three
	// losing it, fails before any of the outcomes below are read.
	var discarding []string
	for _, tc := range wireCharacterization() {
		if tc.readErrorIsNotAnError {
			discarding = append(discarding, tc.name)
		}
	}
	require.Equal(t, []string{"GetSettingsKeys", "RotateSettingsKeys", "DeleteSettingsKey"}, discarding,
		"only settings_keys_client.go's three methods discard their body-read error")

	// GetSettingsKeys uses the body, so a partial one still fails -- as the decode error it is
	// today, not as a read error.
	t.Run("GetSettingsKeys surfaces a mid-read failure as a decode failure", func(t *testing.T) {
		client := clientOverTruncatedResponse(t, http.StatusOK, `{"keys":[`)

		keys, err := client.GetSettingsKeys(context.Background(), charAccessToken)
		require.Error(t, err)
		assert.Nil(t, keys)
	})

	// Rotate and Delete use no body at all, and both report the success the status carried.
	t.Run("RotateSettingsKeys reports the rotation the auth server completed", func(t *testing.T) {
		client := clientOverTruncatedResponse(t, http.StatusOK, `{"ro`)

		assert.NoError(t, client.RotateSettingsKeys(context.Background(), charAccessToken))
	})

	t.Run("DeleteSettingsKey reports the deletion the auth server completed", func(t *testing.T) {
		client := clientOverTruncatedResponse(t, http.StatusOK, `{"de`)

		assert.NoError(t, client.DeleteSettingsKey(context.Background(), charAccessToken, 7))
	})

	// And the status still decides: a mid-read failure on a non-2xx is still that non-2xx,
	// classified from whatever prefix arrived.
	t.Run("a non-2xx is still classified when the read fails partway", func(t *testing.T) {
		client := clientOverTruncatedResponse(t, http.StatusForbidden, `{"error_code":"nope"`)

		err := client.RotateSettingsKeys(context.Background(), charAccessToken)
		require.Error(t, err)

		var apiErr *APIError
		require.True(t, errors.As(err, &apiErr))
		assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	})
}

// clientOverTruncatedResponse returns a client whose transport answers status and prefix and then
// fails the read. httptest cannot do this: a handler that writes and panics still produces a body
// the client reads cleanly on a short response, so the failure is injected at the RoundTripper.
func clientOverTruncatedResponse(t *testing.T, status int, prefix string) *AuthServerClient {
	t.Helper()

	client := NewAuthServerClient("http://auth.example.com")
	client.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(&failingBody{prefix: []byte(prefix)}),
				Request:    r,
			}, nil
		}),
	}
	return client
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
