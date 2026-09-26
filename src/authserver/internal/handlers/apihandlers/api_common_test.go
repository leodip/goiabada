package apihandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/testutil"
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

// TestWriteJSONError_GenericConditionEnvelopes is seam 4's retired-code table: one row per
// condition decision 18 flattened, naming the survivor and the status it rides on.
//
// The rows carry the sentence as well as the code, because that is the half of the flattening that
// could have gone wrong without anything failing. Fifteen spellings became three, and every one of
// the 115 sites kept the message it already wrote: an operator reading "Invalid user ID" and a
// console forwarding it to a person see exactly what they saw before, and the code stopped being
// fifteen names for three conditions. A change that flattened the description alongside the code
// would pass a status assertion and lose the only part of the body a human reads.
//
// api_error_code_lint_test.go is what stops a fourth spelling appearing; this is what says the
// three mean what they say.
func TestWriteJSONError_GenericConditionEnvelopes(t *testing.T) {
	tests := []struct {
		name        string
		description string
		code        string
		status      int
		retired     string // one of the spellings this row replaced, for the reader
	}{
		{
			name:        "a rejected value",
			description: "Invalid user ID",
			code:        "VALIDATION_ERROR",
			status:      http.StatusBadRequest,
			retired:     "INVALID_USER_ID",
		},
		{
			name:        "a body that will not parse",
			description: "Invalid request body",
			code:        "INVALID_REQUEST_BODY",
			status:      http.StatusBadRequest,
			retired:     "INVALID_REQUEST",
		},
		{
			name:        "an absent entity",
			description: "User not found",
			code:        "NOT_FOUND",
			status:      http.StatusNotFound,
			retired:     "USER_NOT_FOUND",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeJSONError(rr, test.description, test.code, test.status)

			assert.Equal(t, test.status, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, test.code, code)
			assert.NotEqual(t, test.retired, code, "the retired spelling must not come back")
			assert.Equal(t, test.description, description,
				"flattening the code must not flatten the sentence a person reads")
		})
	}
}

// writeListSaveFailure is the one answer every list save gives a failed transaction. The two
// conflicts a caller resolves by reading the list again, an outdated loaded list and a concurrent
// duplicate the engine refused on a unique key, are 409 CONCURRENT_UPDATE and log nothing, since
// nobody has to act on them; anything else is the one 500 with the caller's attributes on its record.
// Each conflict is matched through a wrap, which is how it arrives: the transaction body wraps what
// the data layer returns, and the helper hands the body's error back (#428).
func TestWriteListSaveFailure(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantStatus      int
		wantCode        string
		wantDescription string
	}{
		{
			name:            "an outdated loaded list is 409 CONCURRENT_UPDATE",
			err:             errs.Wrap(errListChanged, "inside the transaction"),
			wantStatus:      http.StatusConflict,
			wantCode:        "CONCURRENT_UPDATE",
			wantDescription: "changed by another save after it was loaded",
		},
		{
			name:            "a unique-key refusal is 409 CONCURRENT_UPDATE",
			err:             errs.Wrap(data.ErrUniqueViolation, "database error creating web origin"),
			wantStatus:      http.StatusConflict,
			wantCode:        "CONCURRENT_UPDATE",
			wantDescription: "changed by another save at the same moment",
		},
		{
			name:            "anything else is the one 500",
			err:             errs.New("the disk is full"),
			wantStatus:      http.StatusInternalServerError,
			wantCode:        "INTERNAL_SERVER_ERROR",
			wantDescription: "Request Id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := testutil.CaptureSlog(t)
			rr := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/7/redirect-uris", nil)

			writeListSaveFailure(rr, r, test.err, "client_id", int64(7))

			assert.Equal(t, test.wantStatus, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, test.wantCode, code)
			assert.Contains(t, description, test.wantDescription)

			if test.wantStatus == http.StatusInternalServerError {
				attrs := oneErrorRecord(t, capture)
				assert.EqualValues(t, 7, attrs["client_id"], "the caller's attributes reach the record")
			} else {
				assert.Empty(t, capture.Records(), "a conflict the caller resolves is not logged")
			}
		})
	}
}
