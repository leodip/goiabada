package apihandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeValidationError picks its arm with errors.As rather than a type switch, and these rows are
// the reason. A type switch reads only the outermost value, so one wrap anywhere between the
// validator and the handler sent a localized error to the default arm: the catalog key flattened to
// VALIDATION_ERROR and the description became the English fallback with the wrapper's prefix glued
// to the front. Nothing about that is visible at the call site, which is why it is pinned here
// (#279 decision 6).
//
// The wrapped rows fail against the type switch this stage replaced; the bare rows are its
// behaviour, kept so the As rewrite cannot quietly change which arm an unwrapped error takes.

// decodeErrorEnvelope reads the admin/account API error body back off the recorder.
func decodeErrorEnvelope(t *testing.T, rr *httptest.ResponseRecorder) (code string, description string) {
	t.Helper()
	var body struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	return body.ErrorCode, body.ErrorDescription
}

func TestWriteValidationError(t *testing.T) {
	localized := i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil)
	const localizedText = "Please enter a valid email address."

	detail := customerrors.NewErrorDetail("some_code", "The value is not acceptable.")

	tests := []struct {
		name            string
		err             error
		wantCode        string
		wantDescription string
	}{
		{
			name:            "localized error",
			err:             localized,
			wantCode:        i18n.ErrCodeEmailInvalidFormat,
			wantDescription: localizedText,
		},
		{
			name:            "wrapped localized error keeps its catalog key and its text",
			err:             errs.Wrap(localized, "unable to validate the account's email"),
			wantCode:        i18n.ErrCodeEmailInvalidFormat,
			wantDescription: localizedText,
		},
		{
			name:            "error detail",
			err:             detail,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "The value is not acceptable.",
		},
		{
			name:            "wrapped error detail keeps its own description",
			err:             errs.Wrap(detail, "unable to validate the request"),
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "The value is not acceptable.",
		},
		{
			name:            "any other error falls through to its own text",
			err:             errs.New("something else entirely"),
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "something else entirely",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeValidationError(rr, httptest.NewRequest(http.MethodPost, "/api/v1/account/email", nil), test.err)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, test.wantCode, code)
			assert.Equal(t, test.wantDescription, description)
		})
	}
}
