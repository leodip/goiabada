package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/api"
)

// The admin API's email templates (#818 decision 10), in its settings domain: one language of one
// email is what is read, saved and reset. The email and the language come from the console's own
// URL, so each is escaped as one path segment.

func (c *AuthServerClient) emailTemplateURL(email string, language ...string) string {
	target := fmt.Sprintf("%s/api/v1/admin/email-templates/%s", c.baseURL, url.PathEscape(email))
	for _, l := range language {
		target += "/" + url.PathEscape(l)
	}
	return target
}

// GetEmailTemplates answers every email with the status of each of its six languages, in the order
// Goiabada lists them.
func (c *AuthServerClient) GetEmailTemplates(ctx context.Context, accessToken string) ([]api.EmailTemplateSummaryResponse, error) {
	response, err := execute[api.GetEmailTemplatesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/email-templates", c.baseURL),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.EmailTemplates, nil
}

// GetEmailTemplate answers one email: its placeholders, whether it has a button, and each
// language's built-in text, editor's text, status and problems.
func (c *AuthServerClient) GetEmailTemplate(ctx context.Context, accessToken string, email string) (*api.EmailTemplateResponse, error) {
	response, err := execute[api.GetEmailTemplateResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           c.emailTemplateURL(email),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.EmailTemplate, nil
}

// SaveEmailTemplate saves the whole text of one language of an email, and answers that language as
// the read gives it.
func (c *AuthServerClient) SaveEmailTemplate(ctx context.Context, accessToken string, email, language string,
	request *api.SaveEmailTemplateRequest) (*api.EmailTemplateLanguageResponse, error) {
	return execute[api.EmailTemplateLanguageResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           c.emailTemplateURL(email, language),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// ResetEmailTemplate removes the edit of one language of an email, which is then sent with the
// built-in text. The API answers 204 whether or not there was an edit.
func (c *AuthServerClient) ResetEmailTemplate(ctx context.Context, accessToken string, email, language string) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           c.emailTemplateURL(email, language),
		successStatus: http.StatusNoContent,
	})
	return err
}
