package oauth

import (
	"errors"
	"testing"
)

// TestErrorDetail_Error_EveryShape pins Error()'s text for every shape a detail can take. The
// text was a map's keys sorted and joined until #442 made the detail a struct, and every wrapped
// error that reaches a log record carries it, so the struct has to render the same bytes: the
// expected strings here were recorded from the map, not derived from the struct.
func TestErrorDetail_Error_EveryShape(t *testing.T) {
	tests := []struct {
		name   string
		detail *ErrorDetail
		want   string
	}{
		{
			name:   "code and description only",
			detail: NewErrorDetail("invalid_request", "The client_id parameter is missing."),
			want:   "code: invalid_request; description: The client_id parameter is missing.",
		},
		{
			name:   "with status",
			detail: NewErrorDetailWithHTTPStatus("invalid_grant", "The user account is disabled.", 400),
			want:   "code: invalid_grant; description: The user account is disabled.; httpStatusCode: 400",
		},
		{
			name: "with status and WWW-Authenticate",
			detail: NewErrorDetailWithHTTPStatus("invalid_client", "Client authentication failed.", 401).
				WithWWWAuthenticate(`Basic realm="goiabada"`),
			want: `code: invalid_client; description: Client authentication failed.; httpStatusCode: 401; wwwAuthenticate: Basic realm="goiabada"`,
		},
		{
			name:   "with WWW-Authenticate and no status",
			detail: NewErrorDetail("invalid_token", "The access token is expired.").WithWWWAuthenticate("Bearer"),
			want:   "code: invalid_token; description: The access token is expired.; wwwAuthenticate: Bearer",
		},
		{
			name:   "status above the range reads as no status",
			detail: NewErrorDetailWithHTTPStatus("invalid_request", "Above max.", 600),
			want:   "code: invalid_request; description: Above max.",
		},
		{
			name:   "status below the range reads as no status",
			detail: NewErrorDetailWithHTTPStatus("invalid_request", "Below min.", 99),
			want:   "code: invalid_request; description: Below min.",
		},
		{
			name:   "no code and no status is the description alone",
			detail: NewErrorDetail("", "Test error string"),
			want:   "Test error string",
		},
		{
			name:   "no code and no status is the description alone, a challenge notwithstanding",
			detail: NewErrorDetail("", "Test error string").WithWWWAuthenticate("Bearer"),
			want:   "Test error string",
		},
		{
			name:   "no code with a status still lists every entry",
			detail: NewErrorDetailWithHTTPStatus("", "Test error string", 500),
			want:   "code: ; description: Test error string; httpStatusCode: 500",
		},
		{
			name:   "an empty description is still listed",
			detail: NewErrorDetail("server_error", ""),
			want:   "code: server_error; description: ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.detail.Error(); got != tc.want {
				t.Errorf("Error():\n  got  %q\n  want %q", got, tc.want)
			}
		})
	}
}

// TestErrorDetail_Is_StatusAndChallenge pins the two equalities the map gave for free and the struct
// has to keep: a status outside 100-599 is no status at all, and the challenge takes part in the
// comparison.
func TestErrorDetail_Is_StatusAndChallenge(t *testing.T) {
	if !errors.Is(NewErrorDetailWithHTTPStatus("invalid_request", "x", 600), NewErrorDetail("invalid_request", "x")) {
		t.Error("Expected an out-of-range status to equal no status")
	}
	if errors.Is(NewErrorDetail("invalid_token", "x").WithWWWAuthenticate("Bearer"),
		NewErrorDetail("invalid_token", "x").WithWWWAuthenticate("Basic")) {
		t.Error("Expected two differing challenges not to match")
	}
}
