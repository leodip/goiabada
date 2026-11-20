//go:build !race

package server

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openAPISchema is the part of a Schema Object this file reads.
type openAPISchema struct {
	Ref        string                   `yaml:"$ref"`
	Type       string                   `yaml:"type"`
	Nullable   bool                     `yaml:"nullable"`
	Properties map[string]openAPISchema `yaml:"properties"`
	Required   []string                 `yaml:"required"`
}

// A connected client with no stored consent is answered with `consent: null` (#135 decision 4).
// OpenAPI 3.0.3 §4.7.24.2 applies `nullable` only beside a `type` in the same Schema Object, and
// a `$ref`'s siblings are ignored, so a `nullable` wrapper around a reference to a non-nullable
// object still rejects that null. The schema the property lands on must itself declare
// `type: object` and `nullable: true`, and the property stays required.
func TestOpenAPI_ConnectedClientConsentAcceptsNull(t *testing.T) {
	doc := specDocument(t)

	var row openAPISchema
	node, ok := doc.Components.Schemas["ConnectedClientResponse"]
	require.True(t, ok, "ConnectedClientResponse is declared")
	require.NoError(t, node.Decode(&row))

	consent, ok := row.Properties["consent"]
	require.True(t, ok, "ConnectedClientResponse declares consent")
	assert.True(t, slices.Contains(row.Required, "consent"), "consent is required, null or not")

	if consent.Ref != "" {
		name, found := strings.CutPrefix(consent.Ref, "#/components/schemas/")
		require.True(t, found, "consent references a component schema: %s", consent.Ref)
		target, ok := doc.Components.Schemas[name]
		require.True(t, ok, "%s is declared", name)
		consent = openAPISchema{}
		require.NoError(t, target.Decode(&consent))
	}

	assert.Equal(t, "object", consent.Type, "the consent schema declares its type beside nullable")
	assert.True(t, consent.Nullable, "the consent schema is nullable where its type is declared")
	assert.ElementsMatch(t, []string{"id", "scope", "grantedAt"}, consent.Required)
}
