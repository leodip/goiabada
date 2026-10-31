package adminlegaldocumenthandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// legalDocumentPreviewAPI is what the preview needs: the auth server's rendering.
type legalDocumentPreviewAPI interface {
	PreviewLegalDocument(ctx context.Context, accessToken string, markdown string) (string, error)
}

// previewInput is what the editor's script sends: the text as it is in the editor, saved or not.
type previewInput struct {
	Markdown string `json:"markdown"`
}

// previewOutput is the HTML the auth server rendered, by the renderer its public pages use.
type previewOutput struct {
	Html string `json:"html"`
}

// HandlePreviewPost answers the editor's text rendered as the document's public page renders it.
// The console renders nothing itself: the auth server's renderer is the one that keeps raw HTML,
// script addresses and images out of a document (#622 decision 4).
func HandlePreviewPost(
	httpHelper HttpHelper,
	apiClient legalDocumentPreviewAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}
		var input previewInput
		if decodeErr := json.Unmarshal(body, &input); decodeErr != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		html, err := apiClient.PreviewLegalDocument(r.Context(), jwtInfo.TokenResponse.AccessToken, input.Markdown)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		httpHelper.EncodeJSON(w, r, previewOutput{Html: html})
	}
}
