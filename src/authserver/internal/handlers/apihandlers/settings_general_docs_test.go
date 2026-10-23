package apihandlers

// The App name's request schema, held to the names the general settings save accepts.
//
// The save measures the App name once trimmed (#646 decision 3), and a length bound in openapi.yaml
// applies to the string as sent, before any trimming, so a bound there of 30 refused a name the save
// accepts and stores. A client or gateway that validates requests against the published schema then
// refuses it before the server sees it. It reads files and nothing else.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/web"
)

func TestSettingsGeneralDocs_TheAppNameSchemaAdmitsWhatTheSaveAccepts(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type      string `yaml:"type"`
					MinLength *int   `yaml:"minLength"`
					MaxLength *int   `yaml:"maxLength"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(web.OpenAPISpec(), &doc))
	appName, ok := doc.Components.Schemas["UpdateSettingsGeneralRequest"].Properties["appName"]
	require.True(t, ok, "%s gives UpdateSettingsGeneralRequest no appName", openAPISpecPath)
	require.Equal(t, "string", appName.Type)

	// JSON Schema counts a string's length in code points, as the save counts these.
	for _, name := range []string{
		"  " + strings.Repeat("é", accountvalidation.MaxAppNameLength) + "\t",
		strings.Repeat(" ", 40) + "Goiabada" + strings.Repeat(" ", 40),
		"x",
	} {
		_, err := accountvalidation.ValidateAppName(name)
		require.NoError(t, err, "the save refuses %q", name)
		length := utf8.RuneCountInString(name)
		if appName.MaxLength != nil {
			assert.LessOrEqual(t, length, *appName.MaxLength, "%s's maxLength refuses %q, which the save accepts", openAPISpecPath, name)
		}
		if appName.MinLength != nil {
			assert.GreaterOrEqual(t, length, *appName.MinLength, "%s's minLength refuses %q, which the save accepts", openAPISpecPath, name)
		}
	}
}
