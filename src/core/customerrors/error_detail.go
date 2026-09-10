package customerrors

import (
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNoAuthContext = NewErrorDetail("no_auth_context", "no auth context in session")
	ErrUserDisabled  = NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400)
	// ErrClientDisabled is a comparison target, like ErrUserDisabled: the token validator
	// constructs this same value and errors.Is matches it by value through Is below.
	//
	// It exists because it is the one invalid_grant a password grant can produce without any
	// credential having been read. The check runs before the grant-type switch, so treating
	// every invalid_grant on a password grant as a guess against the account would charge an
	// account's failure budget, and write a ropc_auth_failed audit row naming a username
	// nothing ever compared, for a request that merely named a disabled client (#219).
	ErrClientDisabled = NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400)
	// ErrCodeRedirectURIDeregistered is a comparison target, like the two above: the token
	// validator constructs this same value when redeeming an authorization code whose own
	// redirect URI is no longer registered on the client, and errors.Is matches it by value
	// through Is below.
	// That is what makes the audit decision and the wire message one fact rather than two
	// that can drift (#241 decision 10).
	//
	// The message is legible where every refusal around it is a flat "Code is invalid." Two
	// things pay for that. The check runs below client authentication and PKCE, so whoever
	// reads this has either authenticated as the client or proved possession of the verifier,
	// and it already submitted both the redirect URI and the client identifier, so nothing
	// here is news to them. And the person who needs to read it is an administrator who
	// rotated a callback while a code was outstanding: the generic "Invalid redirect_uri."
	// that a submitted-value mismatch returns also means "you sent one that differs from the
	// code's", so reusing it would leave them unable to tell which of the two happened.
	ErrCodeRedirectURIDeregistered = NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The redirect URI recorded on this authorization code is no longer registered on the client, so the code can no longer be redeemed.", 400)
)

type ErrorDetail struct {
	details map[string]string
}

func NewErrorDetail(code string, description string) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	return &ErrorDetail{
		details: details,
	}
}

func NewErrorDetailWithHttpStatusCode(code string, description string, httpStatusCode int) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	if httpStatusCode >= 100 && httpStatusCode < 600 {
		details["httpStatusCode"] = fmt.Sprintf("%d", httpStatusCode)
	}
	return &ErrorDetail{
		details: details,
	}
}

// NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate creates an ErrorDetail with WWW-Authenticate header info.
// Per RFC 6749 Section 5.2, when the client attempted to authenticate via the Authorization header
// and authentication failed, the server MUST respond with 401 and include WWW-Authenticate.
func NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate(code string, description string, httpStatusCode int, wwwAuthenticate string) *ErrorDetail {
	details := make(map[string]string)
	details["code"] = code
	details["description"] = description
	if httpStatusCode >= 100 && httpStatusCode < 600 {
		details["httpStatusCode"] = fmt.Sprintf("%d", httpStatusCode)
	}
	if wwwAuthenticate != "" {
		details["wwwAuthenticate"] = wwwAuthenticate
	}
	return &ErrorDetail{
		details: details,
	}
}

func (e *ErrorDetail) Error() string {
	if e.details["code"] == "" && e.details["httpStatusCode"] == "" {
		return e.details["description"]
	}

	// Create a slice of keys
	keys := make([]string, 0, len(e.details))
	for k := range e.details {
		keys = append(keys, k)
	}

	// Sort the keys alphabetically
	sort.Strings(keys)

	var sb strings.Builder
	for _, key := range keys {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%v: %v", key, e.details[key])
	}
	return sb.String()
}

// WithDescription returns a copy of e carrying description in place of its own, leaving the
// receiver untouched.
//
// It clones the details map rather than round-tripping through GetCode, GetHttpStatusCode,
// GetWWWAuthenticate and the four-argument constructor. The round-trip reads correct today and
// silently drops any detail key added later, and Is compares len(details) as well as every
// entry, so a dropped key would quietly change an equality that ErrUserDisabled and ErrClientDisabled
// are compared by (#213).
func (e *ErrorDetail) WithDescription(description string) *ErrorDetail {
	details := make(map[string]string, len(e.details))
	for k, v := range e.details {
		details[k] = v
	}
	details["description"] = description
	return &ErrorDetail{
		details: details,
	}
}

func (e *ErrorDetail) GetCode() string {
	return e.details["code"]
}

func (e *ErrorDetail) GetDescription() string {
	return e.details["description"]
}

func (e *ErrorDetail) GetHttpStatusCode() int {
	statusCode := e.details["httpStatusCode"]
	if statusCode == "" {
		return 0
	}

	httpStatusCode := 0
	_, err := fmt.Sscanf(statusCode, "%d", &httpStatusCode)
	if err != nil {
		return 0
	}
	return httpStatusCode
}

// GetWWWAuthenticate returns the WWW-Authenticate header value if set.
// Per RFC 6749 Section 5.2, this should be included in 401 responses when
// the client attempted to authenticate via the Authorization header.
func (e *ErrorDetail) GetWWWAuthenticate() string {
	return e.details["wwwAuthenticate"]
}

// Is reports whether e carries the same details as target, which is what makes
// errors.Is(err, ErrUserDisabled) match a copy the token validator rebuilt rather than the sentinel
// value itself. ErrUserDisabled, ErrClientDisabled and ErrCodeRedirectURIDeregistered are never
// returned by identity: the validator constructs an equal value at the point of failure, so without
// this method errors.Is would fall back to == and match none of the three. ErrNoAuthContext is
// returned by identity and would match either way.
//
// Every entry is compared, and the lengths first, so a detail key added later cannot quietly widen
// an equality: two ErrorDetails agreeing on code and description but differing in httpStatusCode
// are different errors, which is the distinction ErrUserDisabled and ErrClientDisabled turn on.
//
// It replaces IsError, whose signature took a *ErrorDetail and so could only be called after a
// bare type assertion had already found one. A target of any other type is not this error (#279).
func (e *ErrorDetail) Is(target error) bool {
	targetDetail, ok := target.(*ErrorDetail)
	if !ok || targetDetail == nil {
		return false
	}

	if len(e.details) != len(targetDetail.details) {
		return false
	}

	for key, value := range e.details {
		targetValue, exists := targetDetail.details[key]
		if !exists || value != targetValue {
			return false
		}
	}

	return true
}
