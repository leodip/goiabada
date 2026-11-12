package apiclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

// The brands' decode half (#810 decision 5): the Branding pages draw a brand from every field the
// admin API answers, and its swatches from the themes' palettes, so this pins each of them off the
// bytes the auth server writes.

const brandBodyFields = `"id":7,"name":"Spring","appearance":"dark","theme":"plum","isDefault":true,"clientCount":3,` +
	`"createdAt":"2026-11-09T10:00:00Z","updatedAt":"2026-11-09T11:30:00Z"`

func TestAuthServerClient_GetBrandByIdDecodesEveryFieldTheConsoleBinds(t *testing.T) {
	client, recorded := serves(t, `{"brand":{`+brandBodyFields+`}}`)

	brand, err := client.GetBrandById(context.Background(), "an-access-token", 7)
	require.NoError(t, err)
	require.NotNil(t, brand)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/brands/7", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, int64(7), brand.Id)
	assert.Equal(t, "Spring", brand.Name)
	assert.Equal(t, "dark", brand.Appearance)
	assert.Equal(t, "plum", brand.Theme)
	assert.True(t, brand.IsDefault, "the list and the delete page mark the default from the server's flag")
	assert.Equal(t, 3, brand.ClientCount, "the list, the brand's page and the delete page say how many clients use it")
	require.NotNil(t, brand.CreatedAt)
	assert.Equal(t, time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), brand.CreatedAt.UTC())
	require.NotNil(t, brand.UpdatedAt)
	assert.Equal(t, time.Date(2026, 11, 9, 11, 30, 0, 0, time.UTC), brand.UpdatedAt.UTC())
}

func TestAuthServerClient_GetAllBrandsDecodesTheListInTheServersOrder(t *testing.T) {
	client, recorded := serves(t, `{"brands":[{"id":3,"name":"Autumn","appearance":"auto","theme":"tangerine","isDefault":false},`+
		`{`+brandBodyFields+`}]}`)

	brands, err := client.GetAllBrands(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/brands", gotPath)

	require.Len(t, brands, 2)
	assert.Equal(t, "Autumn", brands[0].Name)
	assert.False(t, brands[0].IsDefault)
	assert.Equal(t, "Spring", brands[1].Name)
	assert.True(t, brands[1].IsDefault)
}

func TestAuthServerClient_GetBrandThemesDecodesBothPalettesOfEachTheme(t *testing.T) {
	client, recorded := serves(t, `{"brandThemes":[`+
		`{"key":"blueberry","light":{"canvas":"#f4f5f7","ink-muted":"#535c6c"},"dark":{"canvas":"#0f1217","ink-muted":"#a0a8b6"}},`+
		`{"key":"high-contrast","light":{"canvas":"#ffffff"},"dark":{"canvas":"#000000"}}]}`)

	themes, err := client.GetBrandThemes(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/brand-themes", gotPath)

	require.Len(t, themes, 2)
	assert.Equal(t, "blueberry", themes[0].Key)
	assert.Equal(t, map[string]string{"canvas": "#f4f5f7", "ink-muted": "#535c6c"}, themes[0].Light)
	assert.Equal(t, map[string]string{"canvas": "#0f1217", "ink-muted": "#a0a8b6"}, themes[0].Dark)
	assert.Equal(t, "high-contrast", themes[1].Key)
	assert.Equal(t, "#000000", themes[1].Dark["canvas"])
}

// A refusal of a brand's save says which member of the body it is about in error_field, a JSON
// Pointer such as /footerLinks/1/url (#814 decision 10), which the brand editor marks its input from;
// a refusal without one, as every other refusal is, carries none.
func TestAuthServerClient_ABrandRefusalCarriesTheMemberItIsAbout(t *testing.T) {
	client, _ := servesStatus(t, http.StatusBadRequest, `{"error_code":"handler.brand.footer_link_url_invalid",`+
		`"error_description":"Link 2's URL must be an https: address.","error_field":"/footerLinks/1/url"}`)

	_, err := client.UpdateBrand(context.Background(), "an-access-token", 7, &api.UpdateBrandRequest{Name: "Spring"})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, "handler.brand.footer_link_url_invalid", apiErr.Code)
	assert.Equal(t, "Link 2's URL must be an https: address.", apiErr.Message)
	assert.Equal(t, "/footerLinks/1/url", apiErr.Field)

	client, _ = servesStatus(t, http.StatusBadRequest, `{"error_code":"handler.brand.support_phone_invalid",`+
		`"error_description":"Enter the phone number with its country code."}`)
	_, err = client.UpdateBrand(context.Background(), "an-access-token", 7, &api.UpdateBrandRequest{Name: "Spring"})
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, "handler.brand.support_phone_invalid", apiErr.Code)
	assert.Empty(t, apiErr.Field)
}
