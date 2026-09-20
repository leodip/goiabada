package customerrors

import (
	"fmt"
	"sort"
	"strings"
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
// GetWWWAuthenticate and a constructor. The round-trip reads correct today and silently drops any
// detail key added later, and Is compares len(details) as well as every entry, so a dropped key
// would quietly change an equality the auth server's grant sentinels are compared by (#213).
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

// WithWWWAuthenticate returns a copy of e carrying wwwAuthenticate, leaving the receiver
// untouched. It is WithDescription's sibling and clones the same way, for the same reason.
//
// An empty value adds no entry, which is not cosmetic: Is compares len(details) before comparing
// any of them, so a detail present-but-empty is a different error from one that does not carry
// the key at all. That guard came from the four-argument constructor this replaced, whose one
// caller now composes NewErrorDetailWithHttpStatusCode with this (#385).
//
// Per RFC 6749 section 5.2, a client that attempted to authenticate through the Authorization
// header and failed must be answered 401 with a WWW-Authenticate header; building that value is
// the auth server's, in authserver/internal/apiresponse, because only a provider issues the
// challenge.
func (e *ErrorDetail) WithWWWAuthenticate(wwwAuthenticate string) *ErrorDetail {
	details := make(map[string]string, len(e.details)+1)
	for k, v := range e.details {
		details[k] = v
	}
	if wwwAuthenticate != "" {
		details["wwwAuthenticate"] = wwwAuthenticate
	}
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
// errors.Is(err, protocolvalidation.ErrUserDisabled) match a copy the token validator rebuilt
// rather than the sentinel value itself. That package's ErrUserDisabled, ErrClientDisabled and
// ErrCodeRedirectURIDeregistered are never returned by identity: the validator constructs an equal
// value at the point of failure, so without this method errors.Is would fall back to == and match
// none of the three. handlerhelpers.ErrNoAuthContext is returned by identity and would match
// either way. All four are the auth server's since #385; core holds only the comparison.
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
