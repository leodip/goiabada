package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasPromptValue_EmptyPrompt(t *testing.T) {
	ac := &AuthContext{Prompt: ""}

	assert.False(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_SingleValue_Match(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_SingleValue_None(t *testing.T) {
	ac := &AuthContext{Prompt: "none"}

	assert.True(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_MultipleValues_LoginConsent(t *testing.T) {
	ac := &AuthContext{Prompt: "login consent"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
	assert.False(t, ac.HasPromptValue("none"))
}

func TestHasPromptValue_MultipleValues_ConsentLogin(t *testing.T) {
	// Order shouldn't matter
	ac := &AuthContext{Prompt: "consent login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
	assert.False(t, ac.HasPromptValue("none"))
}

func TestHasPromptValue_PartialMatch_ShouldNotMatch(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	// "log" is a substring of "login" but shouldn't match
	assert.False(t, ac.HasPromptValue("log"))
	assert.False(t, ac.HasPromptValue("ogin"))
}

func TestHasPromptValue_CaseSensitive(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("LOGIN"))
	assert.False(t, ac.HasPromptValue("Login"))
}

func TestHasPromptValue_WhitespaceHandling(t *testing.T) {
	// strings.Fields handles multiple spaces correctly
	ac := &AuthContext{Prompt: "login  consent"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
}
