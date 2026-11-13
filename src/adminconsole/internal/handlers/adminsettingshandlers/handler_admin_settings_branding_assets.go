package adminsettingshandlers

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// The brand editor's uploads (#813 decision 1): a file picked at one of the kit's fields is sent at
// once to the route of its kind, under /admin/settings/branding/assets, which hands it to the admin
// API as a brand asset of that kind and answers the stored asset, its id and URL, for the editor to
// draw in its sample and name in the slot when the brand is saved. A refused file is answered with the
// admin API's code and sentence, for the editor to show at the field. Each route has its row in the
// console's request-body table, at its kind's byte limit and the multipart framing.

// brandAssetUploadAPI is what an upload needs: the asset stored.
type brandAssetUploadAPI interface {
	UploadBrandAsset(ctx context.Context, accessToken string, kind string, data []byte, filename string) (*api.BrandAssetResponse, error)
}

// brandAssetKind is what the editor and its upload route know of a kind of brand asset (#813 decision
// 3): the types its file picker offers, the refusal of a file over its byte limit, as the admin API
// words it, and the limit it names.
type brandAssetKind struct {
	accept       string
	tooLargeCode string
	maxBytes     int64
}

// brandAssetKinds are the four kinds, by the name their upload route ends in. A logo is a PNG or
// JPEG, which emails draw too (#817 decision 5), a background a PNG, JPEG or WebP, a favicon a PNG,
// and a font a WOFF2 file, which a picker knows by its extension better than by its type.
var brandAssetKinds = map[string]brandAssetKind{
	"logo":       {"image/png,image/jpeg", i18n.ErrCodeImageTooLarge, brandkit.LogoMaxBytes},
	"favicon":    {"image/png", i18n.ErrCodeImageTooLarge, brandkit.FaviconMaxBytes},
	"background": {"image/png,image/jpeg,image/webp", i18n.ErrCodeImageTooLarge, brandkit.BackgroundMaxBytes},
	"font":       {".woff2,font/woff2", i18n.ErrCodeFontTooLarge, brandkit.FontMaxBytes},
}

// brandAssetUploadPath is the console's upload route of a kind.
const brandAssetUploadPath = brandingPath + "/assets/"

// BrandAssetUpload is what the brand editor's upload field of a kind is drawn with: the console's
// route it posts a picked file to, the types the picker offers, and the byte limit with the sentence
// refusing a file over it, which the page's script says without sending a file the admin API would
// refuse.
type BrandAssetUpload struct {
	URL      string
	Accept   string
	MaxBytes int64
	TooLarge string
}

// tooLarge is the sentence refusing a file over kind's byte limit, in the request's language.
func (kind brandAssetKind) tooLarge(ctx context.Context) string {
	return i18n.T(ctx, kind.tooLargeCode, map[string]any{"max": kind.maxBytes})
}

// brandAssetUploads are the four kinds' BrandAssetUpload, by kind.
func brandAssetUploads(ctx context.Context) map[string]BrandAssetUpload {
	uploads := make(map[string]BrandAssetUpload, len(brandAssetKinds))
	for name, kind := range brandAssetKinds {
		uploads[name] = BrandAssetUpload{URL: brandAssetUploadPath + name, Accept: kind.accept,
			MaxBytes: kind.maxBytes, TooLarge: kind.tooLarge(ctx)}
	}
	return uploads
}

// HandleBrandAssetPost - POST /admin/settings/branding/assets/{logo,favicon,background,font}, one
// route per kind: the file in the multipart field "file", uploaded as a brand asset of kind.
//
// A file the request-body table cuts off never reaches the admin API: it is refused as the API refuses
// a file over the kind's limit, naming the limit, so a person sees the same sentence whichever side
// measured it.
func HandleBrandAssetPost(httpHelper HttpHelper, apiClient brandAssetUploadAPI, kind string) http.HandlerFunc {
	limit := brandAssetKinds[kind]
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// The body is bounded before it gets here, by the kind's row in the request-body table. The
		// argument is not a limit: it is how much of the form is held in memory before the rest
		// spills to temporary files.
		//nolint:gosec // G120: bounded by the request-body table, as above; G120 flags every multipart parse
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			var cutOff *http.MaxBytesError
			if errors.As(err, &cutOff) {
				httpHelper.JSONError(w, r, oauth.NewErrorDetailWithHTTPStatus(limit.tooLargeCode,
					limit.tooLarge(r.Context()), http.StatusBadRequest))
				return
			}
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}
		defer func() { _ = file.Close() }()

		data, err := io.ReadAll(file)
		if err != nil {
			httpHelper.JSONError(w, r, errs.Wrap(err, "failed to read the brand asset"))
			return
		}

		asset, err := apiClient.UploadBrandAsset(r.Context(), jwtInfo.TokenResponse.AccessToken, kind, data, header.Filename)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		httpHelper.EncodeJSON(w, r, api.CreateBrandAssetResponse{BrandAsset: *asset})
	}
}
