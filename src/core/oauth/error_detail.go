package oauth

import (
	"strconv"
	"strings"
)

// ErrorDetail is an OAuth error response, RFC 6749 section 5.2: the error code, its description,
// the HTTP status it is answered with and, on a 401, the WWW-Authenticate challenge.
//
// It is a comparable struct, which is what Is compares with ==. A zero status means no status was
// given, and so does one outside 100-599, which the constructor refuses to store; an empty challenge
// means none. It was a map in core/customerrors until #442, with the status formatted into it and
// parsed back out, and the four fields hold exactly what that map could.
type ErrorDetail struct {
	code            string
	description     string
	httpStatus      int
	wwwAuthenticate string
}

func NewErrorDetail(code string, description string) *ErrorDetail {
	return &ErrorDetail{
		code:        code,
		description: description,
	}
}

// NewErrorDetailWithHTTPStatus builds an ErrorDetail answered with httpStatus. A status outside
// 100-599 is not stored, so the detail reads as carrying no status at all.
func NewErrorDetailWithHTTPStatus(code string, description string, httpStatus int) *ErrorDetail {
	e := NewErrorDetail(code, description)
	if httpStatus >= 100 && httpStatus < 600 {
		e.httpStatus = httpStatus
	}
	return e
}

// Error renders the description alone when the detail has neither a code nor a status, and
// otherwise every field it carries as "name: value" pairs joined by "; ", in the order code,
// description, httpStatusCode, wwwAuthenticate. The code and description are always listed, empty
// or not; the status and the challenge only when present. That is the text the map this replaced
// rendered from its sorted keys, and wrapped errors carry it into log records.
func (e *ErrorDetail) Error() string {
	if e.code == "" && e.httpStatus == 0 {
		return e.description
	}

	var sb strings.Builder
	sb.WriteString("code: ")
	sb.WriteString(e.code)
	sb.WriteString("; description: ")
	sb.WriteString(e.description)
	if e.httpStatus != 0 {
		sb.WriteString("; httpStatusCode: ")
		sb.WriteString(strconv.Itoa(e.httpStatus))
	}
	if e.wwwAuthenticate != "" {
		sb.WriteString("; wwwAuthenticate: ")
		sb.WriteString(e.wwwAuthenticate)
	}
	return sb.String()
}

// WithDescription returns a copy of e carrying description in place of its own, leaving the
// receiver untouched.
//
// It copies the struct rather than round-tripping through the accessors and a constructor. The
// round-trip reads correct today and silently drops any field added later, and Is compares every
// field, so a dropped one would quietly change an equality the auth server's grant sentinels are
// compared by (#213).
func (e *ErrorDetail) WithDescription(description string) *ErrorDetail {
	c := *e
	c.description = description
	return &c
}

// WithWWWAuthenticate returns a copy of e carrying wwwAuthenticate, leaving the receiver
// untouched. It is WithDescription's sibling and copies the same way, for the same reason. An empty
// value keeps whatever challenge the receiver carries, none included, so the copy still equals its
// receiver; that is what the map this replaced did, writing the key only for a non-empty value.
//
// Per RFC 6749 section 5.2, a client that attempted to authenticate through the Authorization
// header and failed must be answered 401 with a WWW-Authenticate header; building that value is
// the auth server's, in authserver/internal/protocolvalidation, because only a provider issues the
// challenge (#385).
func (e *ErrorDetail) WithWWWAuthenticate(wwwAuthenticate string) *ErrorDetail {
	c := *e
	if wwwAuthenticate != "" {
		c.wwwAuthenticate = wwwAuthenticate
	}
	return &c
}

func (e *ErrorDetail) Code() string {
	return e.code
}

func (e *ErrorDetail) Description() string {
	return e.description
}

// HTTPStatus returns the status the error is answered with, or 0 when it carries none.
func (e *ErrorDetail) HTTPStatus() int {
	return e.httpStatus
}

// WWWAuthenticate returns the WWW-Authenticate header value if set.
// Per RFC 6749 Section 5.2, this should be included in 401 responses when
// the client attempted to authenticate via the Authorization header.
func (e *ErrorDetail) WWWAuthenticate() string {
	return e.wwwAuthenticate
}

// Is reports whether e carries the same details as target, which is what makes
// errors.Is(err, protocolvalidation.ErrCodeRedirectURIDeregistered) match a copy the token
// validator rebuilt rather than the sentinel value itself. That target is never returned by
// identity: the validator constructs an equal value at the point of failure, so without this method
// errors.Is would fall back to pointer equality and not match it. ceremony.ErrNoAuthContext is
// returned by identity and would match either way. Both are the auth server's since #385; core
// holds only the comparison.
//
// Every field is compared, so two ErrorDetails agreeing on code and description but differing in
// status are different errors, and a field added later takes part without anyone remembering to
// add it here.
//
// It replaces IsError, whose signature took a *ErrorDetail and so could only be called after a
// bare type assertion had already found one. A target of any other type is not this error (#279).
func (e *ErrorDetail) Is(target error) bool {
	targetDetail, ok := target.(*ErrorDetail)
	if !ok || targetDetail == nil {
		return false
	}
	return *e == *targetDetail
}
