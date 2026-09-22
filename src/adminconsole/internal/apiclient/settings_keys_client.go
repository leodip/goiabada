package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// The three methods here are the only ones in the package that read with `body, _ :=`, and they do
// not behave alike: GetSettingsKeys decodes what arrived, so a partial answer fails on the decode,
// while Rotate and Delete use no body at all and report the success the status carried. That is
// what readErrorIsNotAnError preserves. Normalizing them would turn a signing key rotation the auth
// server completed into a 500 the administrator may retry, which is a visible behaviour change on
// the one path where repeating the operation costs something (#386 stage 10, round 2 finding 2).
//
// The response ceiling still holds on all three: an overrun is decided by byte count, not by a read
// error.

// GetSettingsKeys calls GET /api/v1/admin/settings/keys
func (c *AuthServerClient) GetSettingsKeys(ctx context.Context, accessToken string) ([]api.SettingsSigningKeyResponse, error) {
	out, err := execute[api.GetSettingsKeysResponse](ctx, c, accessToken, apiRequest{
		method:                "GET",
		url:                   fmt.Sprintf("%s/api/v1/admin/settings/keys", c.baseURL),
		successStatus:         http.StatusOK,
		readErrorIsNotAnError: true,
	})
	if err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// RotateSettingsKeys calls POST /api/v1/admin/settings/keys/rotate
func (c *AuthServerClient) RotateSettingsKeys(ctx context.Context, accessToken string) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method: "POST",
		url:    fmt.Sprintf("%s/api/v1/admin/settings/keys/rotate", c.baseURL),
		// empty JSON body
		rawBody:               []byte("{}"),
		contentType:           contentTypeJSON,
		successStatus:         http.StatusOK,
		readErrorIsNotAnError: true,
	})
	return err
}

// DeleteSettingsKey calls DELETE /api/v1/admin/settings/keys/{id}
func (c *AuthServerClient) DeleteSettingsKey(ctx context.Context, accessToken string, id int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:                "DELETE",
		url:                   fmt.Sprintf("%s/api/v1/admin/settings/keys/%d", c.baseURL, id),
		successStatus:         http.StatusOK,
		readErrorIsNotAnError: true,
	})
	return err
}
