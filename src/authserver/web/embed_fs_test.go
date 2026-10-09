package web

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OpenAPISpec returns the spec embedded at build time. An empty return would mean
// the //go:embed directive stopped matching the file, which is a build-time
// mistake that otherwise only shows up as an empty response from /openapi.yaml.
func TestOpenAPISpec(t *testing.T) {
	spec := OpenAPISpec()

	assert.NotEmpty(t, spec, "the embedded openapi.yaml must not be empty")
	assert.Contains(t, string(spec), "openapi:",
		"the embedded file must look like an OpenAPI document")
}

// The same bytes are returned on every call, the file's own, so handlers can serve it repeatedly.
func TestOpenAPISpec_IsStable(t *testing.T) {
	onDisk, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)

	assert.Equal(t, onDisk, OpenAPISpec())
	assert.Equal(t, onDisk, OpenAPISpec(), "a second call returns the same bytes")
}
