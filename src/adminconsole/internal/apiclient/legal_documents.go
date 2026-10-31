package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// The admin API's legal documents (#622), in its settings domain. Every operation on one document
// answers the document with its draft and its versions, which is what the console's pages draw.

func (c *AuthServerClient) GetAllLegalDocuments(ctx context.Context, accessToken string) ([]api.LegalDocumentResponse, error) {
	response, err := execute[api.GetLegalDocumentsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents", c.baseURL),
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.LegalDocuments, nil
}

func (c *AuthServerClient) CreateLegalDocument(ctx context.Context, accessToken string,
	request *api.CreateLegalDocumentRequest) (*api.LegalDocumentDetailResponse, error) {
	return execute[api.LegalDocumentDetailResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents", c.baseURL),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
}

// PreviewLegalDocument answers markdown as the document's public page will render it, by the auth
// server's renderer, which is the one that guards what the HTML may hold.
func (c *AuthServerClient) PreviewLegalDocument(ctx context.Context, accessToken string, markdown string) (string, error) {
	response, err := execute[api.PreviewLegalDocumentResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/preview", c.baseURL),
		jsonBody:      api.PreviewLegalDocumentRequest{Markdown: markdown},
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return "", err
	}
	return response.Html, nil
}

func (c *AuthServerClient) GetLegalDocumentById(ctx context.Context, accessToken string,
	legalDocumentId int64) (*api.LegalDocumentDetailResponse, error) {
	return execute[api.LegalDocumentDetailResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d", c.baseURL, legalDocumentId),
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) SaveLegalDocumentDraft(ctx context.Context, accessToken string, legalDocumentId int64,
	request *api.SaveLegalDocumentDraftRequest) (*api.LegalDocumentDetailResponse, error) {
	return execute[api.LegalDocumentDetailResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d/draft", c.baseURL, legalDocumentId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// PublishLegalDocument publishes the document's saved draft as its next version. The request has no
// body: what is published is the draft as stored.
func (c *AuthServerClient) PublishLegalDocument(ctx context.Context, accessToken string,
	legalDocumentId int64) (*api.LegalDocumentDetailResponse, error) {
	return c.legalDocumentAction(ctx, accessToken, legalDocumentId, "publish")
}

func (c *AuthServerClient) RetireLegalDocument(ctx context.Context, accessToken string,
	legalDocumentId int64) (*api.LegalDocumentDetailResponse, error) {
	return c.legalDocumentAction(ctx, accessToken, legalDocumentId, "retire")
}

func (c *AuthServerClient) RestoreLegalDocument(ctx context.Context, accessToken string,
	legalDocumentId int64) (*api.LegalDocumentDetailResponse, error) {
	return c.legalDocumentAction(ctx, accessToken, legalDocumentId, "restore")
}

// legalDocumentAction posts one of the bodiless actions on a document.
func (c *AuthServerClient) legalDocumentAction(ctx context.Context, accessToken string, legalDocumentId int64,
	action string) (*api.LegalDocumentDetailResponse, error) {
	return execute[api.LegalDocumentDetailResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d/%s", c.baseURL, legalDocumentId, action),
		successStatus: http.StatusOK,
	})
}

func (c *AuthServerClient) DeleteLegalDocument(ctx context.Context, accessToken string, legalDocumentId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d", c.baseURL, legalDocumentId),
		successStatus: http.StatusOK,
	})
	return err
}

func (c *AuthServerClient) GetLegalDocumentVersion(ctx context.Context, accessToken string, legalDocumentId int64,
	version int) (*api.GetLegalDocumentVersionResponse, error) {
	return execute[api.GetLegalDocumentVersionResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d/versions/%d", c.baseURL, legalDocumentId, version),
		successStatus: http.StatusOK,
	})
}

// UpdateLegalDocumentApps sets the document's Applies to and replaces its list of apps whole, with
// the list as the page read it, so the auth server refuses a save from an outdated page.
func (c *AuthServerClient) UpdateLegalDocumentApps(ctx context.Context, accessToken string, legalDocumentId int64,
	request *api.UpdateLegalDocumentAppsRequest) (*api.LegalDocumentDetailResponse, error) {
	return execute[api.LegalDocumentDetailResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/legal-documents/%d/apps", c.baseURL, legalDocumentId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
}

// GetClientLegalDocuments reads the client and the legal documents that apply to it, a read of the
// client's that the clients-read scopes reach.
func (c *AuthServerClient) GetClientLegalDocuments(ctx context.Context, accessToken string,
	clientId int64) (*api.GetClientLegalDocumentsResponse, error) {
	return execute[api.GetClientLegalDocumentsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/clients/%d/legal-documents", c.baseURL, clientId),
		successStatus: http.StatusOK,
	})
}
