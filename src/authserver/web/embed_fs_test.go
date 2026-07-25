package web

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// OpenAPISpec returns the spec embedded at build time. An empty return would mean
// the //go:embed directive stopped matching the file, which is a build-time
// mistake that otherwise only shows up as an empty response from /openapi.yaml.
func TestOpenAPISpec(t *testing.T) {
	spec := OpenAPISpec()

	assert.NotEmpty(t, spec, "the embedded openapi.yaml must not be empty")
	assert.True(t, strings.Contains(string(spec), "openapi:"),
		"the embedded file must look like an OpenAPI document")
}

// The same bytes are returned on every call, so handlers can serve it repeatedly.
func TestOpenAPISpec_IsStable(t *testing.T) {
	assert.Equal(t, OpenAPISpec(), OpenAPISpec())
}
