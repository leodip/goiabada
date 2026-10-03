package oauth

import (
	"strings"
	"testing"
)

func TestNewErrorDetail(t *testing.T) {
	code := "E001"
	description := "Test error"
	errorDetail := NewErrorDetail(code, description)

	if errorDetail.Code() != code {
		t.Errorf("Expected code %s, got %s", code, errorDetail.Code())
	}

	if errorDetail.Description() != description {
		t.Errorf("Expected description %s, got %s", description, errorDetail.Description())
	}

	if errorDetail.HTTPStatus() != 0 {
		t.Errorf("Expected HTTP status code 0, got %d", errorDetail.HTTPStatus())
	}
}

func TestNewErrorDetailWithHTTPStatus(t *testing.T) {
	code := "E002"
	description := "Test error with status code"
	httpStatusCode := 400
	errorDetail := NewErrorDetailWithHTTPStatus(code, description, httpStatusCode)

	if errorDetail.Code() != code {
		t.Errorf("Expected code %s, got %s", code, errorDetail.Code())
	}

	if errorDetail.Description() != description {
		t.Errorf("Expected description %s, got %s", description, errorDetail.Description())
	}

	if errorDetail.HTTPStatus() != httpStatusCode {
		t.Errorf("Expected HTTP status code %d, got %d", httpStatusCode, errorDetail.HTTPStatus())
	}
}

func TestErrorDetail_Error(t *testing.T) {
	code := "E003"
	description := "Test error string"
	httpStatusCode := 500
	errorDetail := NewErrorDetailWithHTTPStatus(code, description, httpStatusCode)

	expectedError := "code: E003; description: Test error string; httpStatusCode: 500"
	if errorDetail.Error() != expectedError {
		t.Errorf("Expected error string %s, got %s", expectedError, errorDetail.Error())
	}
}

func TestErrorDetail_Error_OnlyDetailIsAvailable(t *testing.T) {
	errorDetail := NewErrorDetail("", "Test error string")

	expectedError := "Test error string"
	if errorDetail.Error() != expectedError {
		t.Errorf("Expected error string %s, got %s", expectedError, errorDetail.Error())
	}
}

func TestErrorDetail_HTTPStatus_Missing(t *testing.T) {
	errorDetail := NewErrorDetail("E005", "Missing HTTP status code")

	if errorDetail.HTTPStatus() != 0 {
		t.Errorf("Expected HTTP status code 0 for missing status code, got %d", errorDetail.HTTPStatus())
	}
}

func TestNewErrorDetail_LargeValues(t *testing.T) {
	code := strings.Repeat("A", 1000)
	description := strings.Repeat("B", 1000000)
	errorDetail := NewErrorDetail(code, description)

	if errorDetail.Code() != code {
		t.Errorf("Expected code of length %d, got length %d", len(code), len(errorDetail.Code()))
	}

	if errorDetail.Description() != description {
		t.Errorf("Expected description of length %d, got length %d", len(description), len(errorDetail.Description()))
	}
}

func TestNewErrorDetailWithHTTPStatus_EdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		code           string
		description    string
		httpStatusCode int
		expectedCode   int
	}{
		{"Minimum valid HTTP status code", "E006", "Min status", 100, 100},
		{"Maximum valid HTTP status code", "E007", "Max status", 599, 599},
		{"Below minimum HTTP status code", "E008", "Below min", 99, 0},
		{"Above maximum HTTP status code", "E009", "Above max", 600, 0},
		{"Negative HTTP status code", "E010", "Negative", -1, 0},
		{"Zero HTTP status code", "E011", "Zero", 0, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorDetail := NewErrorDetailWithHTTPStatus(tc.code, tc.description, tc.httpStatusCode)
			actualCode := errorDetail.HTTPStatus()
			if actualCode != tc.expectedCode {
				t.Errorf("Expected HTTP status code %d, got %d", tc.expectedCode, actualCode)
			}
		})
	}
}

// TestErrorDetail_WithDescription pins the clone. The method exists so a boundary can rewrite a
// description without rebuilding the detail through four accessors, and the whole value of that is
// that every other field survives: a round-trip through the four-argument constructor reads correct
// today and drops silently whatever is added later (#213).
func TestErrorDetail_WithDescription(t *testing.T) {
	original := NewErrorDetailWithHTTPStatus(
		"invalid_client", "Client authentication failed.", 401).
		WithWWWAuthenticate(`Basic realm="goiabada"`)

	rewritten := original.WithDescription("Client authentication failed (conformed).")

	if rewritten.Description() != "Client authentication failed (conformed)." {
		t.Errorf("Expected the new description, got %s", rewritten.Description())
	}

	// Every other field travels.
	if rewritten.Code() != "invalid_client" {
		t.Errorf("Expected code invalid_client, got %s", rewritten.Code())
	}
	if rewritten.HTTPStatus() != 401 {
		t.Errorf("Expected HTTP status code 401, got %d", rewritten.HTTPStatus())
	}
	if rewritten.WWWAuthenticate() != `Basic realm="goiabada"` {
		t.Errorf("Expected the WWW-Authenticate value to survive, got %s", rewritten.WWWAuthenticate())
	}

	// And the receiver is untouched, which is what makes it safe to call on the package-level
	// comparison targets such as ErrCodeRedirectURIDeregistered.
	if original.Description() != "Client authentication failed." {
		t.Errorf("Expected the receiver to keep its description, got %s", original.Description())
	}
}

// TestErrorDetail_WithWWWAuthenticate pins the sibling setter #385 added when the four-argument
// constructor left core for authserver/internal/apiresponse. The move is only sound if the value
// the composition builds is indistinguishable from what that constructor built, because three
// sentinels are matched through Is and Is compares every field, the challenge included.
func TestErrorDetail_WithWWWAuthenticate(t *testing.T) {
	base := NewErrorDetailWithHTTPStatus("invalid_client", "Client authentication failed.", 401)

	withChallenge := base.WithWWWAuthenticate("Basic")

	if withChallenge.WWWAuthenticate() != "Basic" {
		t.Errorf("Expected the challenge to be set, got %q", withChallenge.WWWAuthenticate())
	}
	// Every other field travels, which is the copy doing its job.
	if withChallenge.Code() != "invalid_client" {
		t.Errorf("Expected code invalid_client, got %s", withChallenge.Code())
	}
	if withChallenge.Description() != "Client authentication failed." {
		t.Errorf("Expected the description to survive, got %s", withChallenge.Description())
	}
	if withChallenge.HTTPStatus() != 401 {
		t.Errorf("Expected HTTP status code 401, got %d", withChallenge.HTTPStatus())
	}

	// The receiver is untouched, which is what makes it safe to call on a package-level value.
	if base.WWWAuthenticate() != "" {
		t.Errorf("Expected the receiver to carry no challenge, got %q", base.WWWAuthenticate())
	}

	// An empty value leaves the detail carrying no challenge, so it still equals its receiver:
	// every non-challenge refusal built through this path has to keep matching its sentinel.
	if base.WithWWWAuthenticate("").Is(base) != true {
		t.Error("Expected an empty challenge to leave the detail equal to its receiver")
	}
	if base.Is(withChallenge) {
		t.Error("Expected a detail carrying a challenge not to equal one without it")
	}
}
