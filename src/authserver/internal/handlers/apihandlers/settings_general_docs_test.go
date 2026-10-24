package apihandlers

// The general settings save's request schema, held to the values the save accepts.
//
// The save measures the App name (#646 decision 3) and the issuer once trimmed, and a length bound
// in openapi.yaml applies to the string as sent, before any trimming, so a bound there of 30 on the
// App name, or of 60 on the issuer, refused a value the save accepts and stores. A client or gateway
// that validates requests against the published schema then refuses it before the server sees it.

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/web"
)

// generalRequestStringProperty is one string property of UpdateSettingsGeneralRequest as the
// published schema declares it, with the length bounds it carries, nil where it carries none.
type generalRequestStringProperty struct {
	Type      string `yaml:"type"`
	MinLength *int   `yaml:"minLength"`
	MaxLength *int   `yaml:"maxLength"`
}

func generalRequestProperty(t *testing.T, name string) generalRequestStringProperty {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]generalRequestStringProperty `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(web.OpenAPISpec(), &doc))
	property, ok := doc.Components.Schemas["UpdateSettingsGeneralRequest"].Properties[name]
	require.True(t, ok, "%s gives UpdateSettingsGeneralRequest no %s", openAPISpecPath, name)
	require.Equal(t, "string", property.Type)
	return property
}

// assertAdmits holds a property's length bounds to admitting value. JSON Schema counts a string's
// length in code points.
func assertAdmits(t *testing.T, name string, property generalRequestStringProperty, value string) {
	t.Helper()
	length := utf8.RuneCountInString(value)
	if property.MaxLength != nil {
		assert.LessOrEqual(t, length, *property.MaxLength, "%s's maxLength on %s refuses %q, which the save accepts", openAPISpecPath, name, value)
	}
	if property.MinLength != nil {
		assert.GreaterOrEqual(t, length, *property.MinLength, "%s's minLength on %s refuses %q, which the save accepts", openAPISpecPath, name, value)
	}
}

func TestSettingsGeneralDocs_TheAppNameSchemaAdmitsWhatTheSaveAccepts(t *testing.T) {
	appName := generalRequestProperty(t, "appName")

	for _, name := range []string{
		"  " + strings.Repeat("é", accountvalidation.MaxAppNameLength) + "\t",
		strings.Repeat(" ", 40) + "Goiabada" + strings.Repeat(" ", 40),
		"x",
	} {
		_, err := accountvalidation.ValidateAppName(name)
		require.NoError(t, err, "the save refuses %q", name)
		assertAdmits(t, "appName", appName, name)
	}
}

// Each issuer is put through the save itself, since the trimming is the handler's.
func TestSettingsGeneralDocs_TheIssuerSchemaAdmitsWhatTheSaveAccepts(t *testing.T) {
	issuer := generalRequestProperty(t, "issuer")

	atTheLimit := "https://auth." + strings.Repeat("a", 60-len("https://auth.")-len(".example.com")) + ".example.com"
	for _, value := range []string{
		"  " + atTheLimit + "\t",
		strings.Repeat(" ", 40) + "https://auth.example.com" + strings.Repeat(" ", 40),
		issuerRuleBaseURL,
	} {
		rr, saved := putGeneralIssuer(t, "https://stored.example.com", value)
		require.Equal(t, http.StatusOK, rr.Code, "the save refuses %q: %s", value, rr.Body.String())
		require.NotNil(t, saved)
		assertAdmits(t, "issuer", issuer, value)
	}
}
