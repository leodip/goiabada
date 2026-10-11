package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

// The admin API answers a refusal in the language the request's Accept-Language names, which is how
// the admin console's pages show the API's refusals in the console's own language: the console sends
// the tag of the catalog its page rendered from on every call (#559 decision 3). Only the
// description is translated; error_code and the status stay what they are, and a request naming no
// language is answered in English, as it was before (#559 decision 2).
//
// This runs the real chain, the API branch's locale middleware included, for one refusal whose
// sentence the API already had in the catalog, and one this change moved there.
func TestAPIRefusals_AreAnsweredInTheRequestsLanguage(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources"

	tests := []struct {
		name       string
		body       api.CreateResourceRequest
		code       string
		english    string
		portuguese string
	}{
		{
			name:       "a sentence the API already had in the catalog",
			body:       api.CreateResourceRequest{ResourceIdentifier: "invalid identifier with spaces", Description: "d"},
			code:       "validator.identifier.invalid_format",
			english:    "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.",
			portuguese: "Formato de identificador inválido. Deve começar com uma letra, pode conter letras, números, hífens e sublinhados, mas não pode terminar com hífen ou sublinhado, nem conter dois hífens ou dois sublinhados consecutivos.",
		},
		{
			name:       "a sentence this change moved into the catalog",
			body:       api.CreateResourceRequest{ResourceIdentifier: "", Description: "d"},
			code:       "VALIDATION_ERROR",
			english:    "Resource identifier is required",
			portuguese: "O identificador do recurso é obrigatório",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, language := range []struct {
				name           string
				acceptLanguage string
				want           string
			}{
				{"no language", "", test.english},
				{"pt-BR", "pt-BR", test.portuguese},
				// The console's own resolution names a catalog's tag, but a caller sending a browser's
				// whole list is matched against the catalogs the same way.
				{"a list whose first match is pt-BR", "fr-CA,fr;q=0.9,pt-BR;q=0.8", test.portuguese},
			} {
				t.Run(language.name, func(t *testing.T) {
					jsonBody, err := json.Marshal(test.body)
					require.NoError(t, err)
					req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
					require.NoError(t, err)
					req.Header.Set("Authorization", "Bearer "+accessToken)
					req.Header.Set("Content-Type", "application/json")
					if language.acceptLanguage != "" {
						req.Header.Set("Accept-Language", language.acceptLanguage)
					}

					resp, err := createHttpClient(t).Do(req)
					require.NoError(t, err)
					defer func() { _ = resp.Body.Close() }()

					assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
					var errResp api.ErrorResponse
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
					assert.Equal(t, test.code, errResp.ErrorCode, "error_code is never translated")
					assert.Equal(t, language.want, errResp.ErrorDescription)
				})
			}
		})
	}
}
