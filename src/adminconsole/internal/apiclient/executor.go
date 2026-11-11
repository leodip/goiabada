package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// generalAPITimeout bounds every request the general AuthServerClient makes but the three that
// send mail, which take mailSendingAPITimeout, and a user's export, which takes
// passThroughAPITimeout. Ten seconds,
// matching oauthclient.TokenExchangeTimeout, sessionbackend's httpBackendTimeout and
// publicsettings.Client's clientTimeout: all four sit on the admin console's page-load path, where a handler
// goroutine held open by an auth server that accepted the connection and then stopped answering
// is the failure this exists to survive. A fourth distinct value on the same path would only invite the question
// of why they differ (#386 decision 6).
//
// It is a constant rather than a setting because the two processes are deployed together, so the
// latency between them is not something an operator varies (#386 decision 7).
const generalAPITimeout = 10 * time.Second

// mailSendingAPITimeout bounds the three calls that make the auth server send mail during the
// request: the test email, creating a user with a setup email, and sending an email verification
// code (#718 decision 8). Fifty seconds outlasts the auth server's SMTP sender, which gives a send
// at most 40, so a slow relay's failure reaches the administrator as the message naming it rather
// than as the console giving up; and the console giving up would cancel the send, so a setup email
// or a verification code to a slow relay would stop being sent at all. It stays under the
// console's 60-second write timeout, so the page still gets its answer.
const mailSendingAPITimeout = 50 * time.Second

// maxAPIResponseBytes is the ceiling on any single admin API response body. 1 MiB, the same value
// as oauthclient.MaxTokenResponseBytes and MaxSessionWireBytes, so the tree has one number of this
// kind rather than four.
//
// ceiling: what it holds, measured on generously populated list elements, is roughly 3,100 groups,
// 5,100 resources, 2,500 permissions on one resource and 1,300 users. Paged endpoints are clamped server side at 200 rows a page, so the
// largest paged response is about 163 KiB and only the unpaginated lists scale with the install.
// Revisit when an install's unpaginated lists approach those counts: exceeding this is a hard
// failure and reaches the administrator as a 500 on an admin page, and the same event is the one
// that should make those endpoints paginate.
//
// Exceeding it is refused rather than cut, by boundedread.Read; the console's error classifier
// falls through to InternalServerError for boundedread.ErrResponseTooLarge, which is the right
// answer for a peer that replied with something absurd.
const maxAPIResponseBytes = 1 << 20

// contentTypeJSON is the request content type all but three of the client's methods carry.
const contentTypeJSON = "application/json"

// apiRequest is what one AuthServerClient method states about itself. Everything else -- building
// the request, carrying the caller's context and bearer token, reading the answer under the
// ceiling, classifying the status and decoding -- is the executor's, and is written once here
// rather than 106 times (#386).
type apiRequest struct {
	// method and url are the verb and the fully built target, parameters and query already
	// substituted by the caller.
	method string
	url    string

	// At most one of jsonBody and rawBody is set. jsonBody is marshalled; rawBody is sent as it
	// stands, which is what the three multipart uploads and the two empty-object POSTs need.
	jsonBody any
	rawBody  []byte

	// contentType is the header the request carries. Empty leaves it unset, which is what
	// DeleteAccountProfilePicture, DeleteUserProfilePicture and DeleteClientLogo do today.
	contentType string

	// successStatus is the single status this method treats as success. anySuccess2xx widens
	// that to the whole 2xx range. Each method keeps exactly the check it has: 200 for most,
	// 201 for the creating ones, and the range for the eleven that were written that way.
	successStatus int
	anySuccess2xx bool

	// readErrorIsNotAnError preserves the `body, _ := io.ReadAll(...)` three methods have today.
	// Set on GetSettingsKeys, RotateSettingsKeys and DeleteSettingsKey, and on nothing else.
	//
	// Rotate and Delete use no body at all, so a read that failed partway through their answer
	// returns nil today and the operation is reported as the success it was. Turning that into an
	// error would make a completed signing key rotation look like a failure the administrator
	// should retry, which is a visible behaviour change on the one path where repeating the
	// operation costs something. GetSettingsKeys does decode, so a partial body still fails --
	// as a decode error, which is what it is today.
	//
	// The ceiling is unaffected: the overrun is decided by byte count, not by a read error, so it
	// still holds on all three.
	readErrorIsNotAnError bool

	// sendsMail gives the call mailSendingAPITimeout instead of generalAPITimeout. Set on
	// SendTestEmail, SendAccountEmailVerification, and CreateUserAdmin when the new user is sent a
	// setup email, and on nothing else (#718 decision 8).
	sendsMail bool
}

// deadline is how long the call may take, its answer read included.
func (r apiRequest) deadline() time.Duration {
	if r.sendsMail {
		return mailSendingAPITimeout
	}
	return generalAPITimeout
}

// execute performs r and decodes the success body into a fresh T.
func execute[T any](ctx context.Context, c *AuthServerClient, accessToken string, r apiRequest) (*T, error) {
	body, err := c.do(ctx, accessToken, r)
	if err != nil {
		return nil, err
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errs.Errorf("failed to decode response: %w", err)
	}
	return &out, nil
}

// do performs r and returns the success body without decoding it, for the methods that return
// nothing and for the two that take the body apart themselves.
func (c *AuthServerClient) do(ctx context.Context, accessToken string, r apiRequest) ([]byte, error) {
	// The deadline is the call's, not the client's, because the three calls that send mail wait
	// longer than the rest. It covers the answer's read, which happens before do returns.
	ctx, cancel := context.WithTimeout(ctx, r.deadline())
	defer cancel()

	req, err := newAPIRequest(ctx, accessToken, r)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := boundedread.Read(resp.Body, maxAPIResponseBytes)
	if readErr != nil && !errors.Is(readErr, boundedread.ErrResponseTooLarge) && r.readErrorIsNotAnError {
		// The read failed partway through and this method does not own that failure. Carry on
		// with what arrived, which is what its `body, _ := io.ReadAll(...)` does today.
		readErr = nil
	}
	if readErr != nil {
		return nil, readErr
	}

	if !r.accepts(resp.StatusCode) {
		return nil, parseAPIError(resp, body)
	}
	return body, nil
}

// passThroughAPITimeout bounds the calls whose answer passes to the browser as it came, a user's
// export, an administrator's download of it or the user's own (#781 decision 5, #782 decision 3):
// five minutes, the bound the auth server gives itself to write
// that answer, so a slow connection still finishes. The body is read after the call returns, by
// whoever copies it on, and the deadline covers that read too.
const passThroughAPITimeout = 5 * time.Minute

// passThrough performs r for an answer to hand on untouched rather than decode: it asks for gzip,
// so the compressed bytes arrive as they were sent and are never unpacked here, and it reads none
// of a success, so the ceiling every other answer is held to does not apply. The caller reads the
// success's body and closes it, which ends the call's deadline. A status r does not accept is
// read under the ceiling and answered as an APIError, as do answers one.
func (c *AuthServerClient) passThrough(ctx context.Context, accessToken string, r apiRequest) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, passThroughAPITimeout)

	req, err := newAPIRequest(ctx, accessToken, r)
	if err != nil {
		cancel()
		return nil, err
	}
	// Set by hand, so the transport neither adds its own nor unpacks the answer: the browser does.
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		return nil, errs.Errorf("failed to make request: %w", err)
	}

	if !r.accepts(resp.StatusCode) {
		defer cancel()
		defer func() { _ = resp.Body.Close() }()
		body, readErr := boundedread.Read(resp.Body, maxAPIResponseBytes)
		if readErr != nil {
			return nil, readErr
		}
		return nil, parseAPIError(resp, body)
	}

	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnClose is a passed-through answer's body, which ends its call's deadline once closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// newAPIRequest builds r's request on ctx, carrying the administrator's bearer token and the
// page's language.
func newAPIRequest(ctx context.Context, accessToken string, r apiRequest) (*http.Request, error) {
	var payload io.Reader
	switch {
	case r.jsonBody != nil:
		jsonData, err := json.Marshal(r.jsonBody)
		if err != nil {
			return nil, errs.Errorf("failed to marshal request: %w", err)
		}
		payload = bytes.NewBuffer(jsonData)
	case r.rawBody != nil:
		payload = bytes.NewBuffer(r.rawBody)
	}

	req, err := http.NewRequestWithContext(ctx, r.method, r.url, payload)
	if err != nil {
		return nil, errs.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	// The language the console's page renders in, so the auth server answers a refusal the page
	// shows in that language when it has the sentence translated (#559 decision 3).
	req.Header.Set("Accept-Language", i18n.CatalogTag(ctx))
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	return req, nil
}

// multipartPicture builds the upload body the three picture endpoints take: one "picture" part
// holding data under filename. It returns the body and the content type the boundary belongs to,
// which is the one place a method supplies its own rather than taking the executor's default.
func multipartPicture(filename string, data []byte) ([]byte, string, error) {
	return multipartFile("picture", filename, data)
}

// multipartFile builds an upload body of one part, field, holding data under filename, and answers
// it with the content type its boundary belongs to: the pictures' "picture", a brand asset's "file".
func multipartFile(field, filename string, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", errs.Errorf("failed to create form file: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", errs.Errorf("failed to write %s data: %w", field, err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", errs.Errorf("failed to close multipart writer: %w", err)
	}

	return buf.Bytes(), writer.FormDataContentType(), nil
}

// accepts reports whether status is the success this method was written to accept.
func (r apiRequest) accepts(status int) bool {
	if r.anySuccess2xx {
		return status >= 200 && status < 300
	}
	return status == r.successStatus
}
