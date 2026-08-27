package sessionstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/pkg/errors"
)

const (
	// sessionEndpointPrefix is where the auth server publishes the five operations. The
	// identifier never appears in it: it travels in the JSON body on every call, because
	// a handle in a request line lands in the auth server's access log and in the log of
	// every proxy between here and it (#266).
	sessionEndpointPrefix = "/api/v1/sessions/"

	// httpBackendTimeout bounds one attempt. It is a session lookup on the request path
	// of every admin console page, so a hung auth server has to become an error quickly
	// rather than holding the browser open.
	httpBackendTimeout = 10 * time.Second

	// transportRetryBackoff is the pause before the single retry a dropped connection
	// gets. Short because the caller is a browser waiting on a page, and it exists at all
	// because an idle keep-alive connection closed by the far end is an ordinary event
	// that should not become a 500 (decision 14, #266).
	transportRetryBackoff = 50 * time.Millisecond
)

// TokenSource supplies the bearer token the session endpoint is behind.
//
// Declared here and implemented by the caller, so this package holds no knowledge of any
// module's credentials and a test can drive the backend with a source that returns a
// constant.
//
// Invalidate is what makes a 401 recoverable: the endpoint answers one when the cached
// token has expired or been revoked, and the backend's answer is to drop the cached token
// and ask once more. A source with nothing cached may do nothing.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Invalidate()
}

// httpBackend is the network transport of Backend: the admin console keeps no database
// connection, so its browser sessions live in a row on the auth server's side of the wire
// and it reaches them through the endpoint (#266).
//
// What crosses is ciphertext the admin console encrypted with its own session keys, so
// the auth server stores bytes it holds no key for. Nothing in this file can read a
// session, and that is the point rather than an accident of layering.
type httpBackend struct {
	baseURL string
	client  *http.Client
	tokens  TokenSource
}

// NewHTTPBackend returns a Backend that reaches the session endpoint at baseURL.
//
// No owner parameter, matching the database backend: the endpoint's handlers hard-wire
// the admin console's owner and accept no other, so there is nothing here a caller could
// name an auth server session with however this is composed.
func NewHTTPBackend(baseURL string, tokens TokenSource) Backend {
	return &httpBackend{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: httpBackendTimeout},
		tokens:  tokens,
	}
}

func (b *httpBackend) Load(ctx context.Context, id string) (*Record, error) {
	var response api.SessionLoadResponse
	if err := b.post(ctx, "load", api.SessionLoadRequest{Id: id}, &response); err != nil {
		return nil, err
	}

	return &Record{
		Data:         []byte(response.Data),
		LastAccessed: response.LastAccessed,
		ExpiresAt:    response.ExpiresAt,
	}, nil
}

func (b *httpBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	var response api.SessionWriteResponse
	request := api.SessionWriteRequest{Id: id, Data: string(data), Authenticated: authenticated}
	if err := b.post(ctx, "create", request, &response); err != nil {
		return time.Time{}, err
	}
	return response.ExpiresAt, nil
}

func (b *httpBackend) Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	var response api.SessionWriteResponse
	request := api.SessionWriteRequest{Id: id, Data: string(data), Authenticated: authenticated}
	if err := b.post(ctx, "update", request, &response); err != nil {
		return time.Time{}, err
	}
	return response.ExpiresAt, nil
}

func (b *httpBackend) Touch(ctx context.Context, id string, authenticated bool) (time.Time, error) {
	var response api.SessionWriteResponse
	request := api.SessionTouchRequest{Id: id, Authenticated: authenticated}
	if err := b.post(ctx, "touch", request, &response); err != nil {
		return time.Time{}, err
	}
	return response.ExpiresAt, nil
}

func (b *httpBackend) Delete(ctx context.Context, id string) error {
	return b.post(ctx, "delete", api.SessionLoadRequest{Id: id}, nil)
}

// post sends one operation and decodes a success body into out, which is nil for the
// operation that answers 204.
//
// Status mapping is the whole contract, and it is decision 14 expressed in one place: 404
// is ErrNotFound, meaning the session is gone, which the store turns into a fresh session;
// every other non-2xx is an error, meaning the lookup could not be performed, which the
// middleware turns into a 500. Collapsing the second into the first would sign every
// administrator out during any interruption between the two processes and leave a warning
// as the only trace.
//
// Create and Delete never see a 404 by the endpoint's own contract: creating names no
// existing session, and deleting one that is already gone is the outcome asked for. If one
// arrives anyway it surfaces as ErrNotFound from those methods, which the store treats as a
// failed save rather than as success, and that is the safe direction.
func (b *httpBackend) post(ctx context.Context, operation string, requestBody interface{}, out interface{}) error {
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, "unable to encode the browser session request")
	}

	// Two independent budgets, deliberately not one. A dropped connection and an expired
	// token are different failures with different remedies, and spending the retry on
	// whichever happened first would leave the other unhandled in the request that met
	// both. Each is allowed exactly once, so at most three attempts leave here and a
	// server answering 401 forever cannot become a loop.
	retriedTransport := false
	refreshedToken := false

	for {
		status, body, err := b.attempt(ctx, operation, encoded)
		if err != nil {
			// Only a failure to reach the endpoint at all is retried. A token source that
			// could not produce a token, or produced an empty one, fails the same way
			// twice, and retrying it would double the cost of an outage without changing
			// its outcome.
			var unreachable *transportError
			if !retriedTransport && errors.As(err, &unreachable) && ctx.Err() == nil {
				retriedTransport = true
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(transportRetryBackoff):
				}
				continue
			}
			return err
		}

		if status == http.StatusUnauthorized && !refreshedToken {
			refreshedToken = true
			b.tokens.Invalidate()
			continue
		}

		return decodeSessionResponse(operation, status, body, out)
	}
}

// attempt performs one request. It returns the status and body of whatever came back, and
// an error otherwise. Only one of those errors is a transportError, meaning nothing came
// back at all, and that is the distinction the retry above is built on: an operation the
// far end never saw is safe to send again, and one whose answer merely went missing is
// not.
//
// The token comes from the source on every attempt rather than being carried in from the
// last one. That is what makes the 401 path work with no second parameter: Invalidate has
// already dropped whatever was cached, so asking again here is asking for a fresh one.
func (b *httpBackend) attempt(ctx context.Context, operation string, encoded []byte) (int, []byte, error) {
	token, err := b.tokens.Token(ctx)
	if err != nil {
		return 0, nil, errors.Wrap(err, "unable to obtain a token for the browser session endpoint")
	}
	if strings.TrimSpace(token) == "" {
		return 0, nil, errors.WithStack(errors.New("the browser session endpoint token source returned an empty token"))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.baseURL+sessionEndpointPrefix+operation, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, errors.Wrap(err, "unable to build the browser session request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := b.client.Do(request)
	if err != nil {
		return 0, nil, &transportError{errors.Wrap(err, "the browser session endpoint could not be reached")}
	}
	defer func() { _ = response.Body.Close() }()

	// Not a transportError, and the distinction is the whole reason this is separate from
	// the Do failure above. Reaching here means the far end answered, so it has already
	// run the operation and committed it; only the body was lost on the way back. Retrying
	// then submits an operation that has already happened, and create is the one that
	// cannot survive that: the second attempt collides with the first attempt's own row on
	// the (owner, session_id_hash) unique index, the endpoint answers 500, and a write that
	// succeeded is reported to the caller as a failure that left an unreachable row behind.
	// A rotation loses more than that, because Regenerate stops before deleting the row it
	// was rotating away.
	//
	// So an answer that could not be read fails once. The retry keeps the case it exists
	// for, an idle keep-alive connection closed by the far end, which is a Do failure with
	// no response at all and therefore nothing the server has acted on (final review,
	// round 2, finding 2).
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSessionResponseBytes))
	if err != nil {
		return 0, nil, errors.Wrap(err, "unable to read the browser session response")
	}

	return response.StatusCode, body, nil
}

// transportError marks a failure to reach the endpoint at all, as opposed to a failure to
// obtain a token or an answer this backend did not like. It is the only failure the single
// retry is spent on, because it is the only one where trying the identical request again
// can plausibly succeed: an idle keep-alive connection closed by the far end is an ordinary
// event, and it should not reach an administrator as a 500 (#266).
type transportError struct {
	err error
}

func (e *transportError) Error() string { return e.err.Error() }

func (e *transportError) Unwrap() error { return e.err }

// maxSessionResponseBytes is the wire ceiling, applied to what comes back as well as to
// what goes out. A response is the auth server's own, so this is not defence against it;
// it is that a store on the request path of every page should not read an unbounded number
// of bytes into memory because something upstream went wrong.
//
// It is the wire ceiling and not MaxSessionDataBytes, because what arrives here is a blob
// inside a JSON envelope: capping the whole body at the blob's own ceiling would truncate
// a maximal session's response before it decoded, which is a failure at exactly the size
// the store admits (final review, round 2, finding 3).
const maxSessionResponseBytes = MaxSessionWireBytes

func decodeSessionResponse(operation string, status int, body []byte, out interface{}) error {
	switch {
	case status == http.StatusNotFound:
		return ErrNotFound
	case status < 200 || status > 299:
		return errors.WithStack(errors.Errorf(
			"the browser session endpoint answered %d to %s", status, operation))
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrapf(err, "unable to decode the browser session response to %s", operation)
	}
	return nil
}
