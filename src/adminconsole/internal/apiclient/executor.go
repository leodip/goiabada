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

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/core/errs"
)

// generalAPITimeout bounds every request the general AuthServerClient makes. Ten seconds,
// matching sessionTokenTimeout and httpBackendTimeout in this package and the SettingsClient
// next door: all four sit on the admin console's page-load path, where a handler goroutine held
// open by an auth server that accepted the connection and then stopped answering is the failure
// this exists to survive. A fourth distinct value on the same path would only invite the question
// of why they differ (#386 decision 6).
//
// It is a constant rather than a setting because the two processes are deployed together, so the
// latency between them is not something an operator varies (#386 decision 7).
const generalAPITimeout = 10 * time.Second

// maxAPIResponseBytes is the ceiling on any single admin API response body. 1 MiB, the same value
// as oauthclient.MaxTokenResponseBytes and MaxSessionWireBytes, so the tree has one number of this
// kind rather than four.
//
// ceiling: what it holds, measured on generously populated list elements, is roughly 3,100 groups,
// 5,100 resources, 2,500 permissions on one resource, 1,300 users and the 250-row phone country
// table nine times over. Paged endpoints are clamped server side at 200 rows a page, so the
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
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
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

// multipartPicture builds the upload body the three picture endpoints take: one "picture" part
// holding data under filename. It returns the body and the content type the boundary belongs to,
// which is the one place a method supplies its own rather than taking the executor's default.
func multipartPicture(filename string, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("picture", filename)
	if err != nil {
		return nil, "", errs.Errorf("failed to create form file: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", errs.Errorf("failed to write picture data: %w", err)
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
