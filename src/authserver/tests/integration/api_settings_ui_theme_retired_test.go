package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// GET and PUT /api/v1/admin/settings/ui-theme are retired (#810): the look is a brand, read and
// changed through /api/v1/admin/brands. A caller holding every scope the operations took finds
// neither, as any address the admin API does not serve.
func TestAPISettingsUITheme_Retired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/ui-theme"

	get := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = get.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, get.StatusCode, "GET is no longer served")

	put := makeAPIRequest(t, "PUT", url, accessToken, map[string]string{"uiTheme": "dark"})
	defer func() { _ = put.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, put.StatusCode, "PUT is no longer served")
}
