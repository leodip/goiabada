package apiclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The brands' decode half (#810 decision 5): the Branding pages draw a brand from every field the
// admin API answers, and its swatches from the themes' palettes, so this pins each of them off the
// bytes the auth server writes.

const brandBodyFields = `"id":7,"name":"Spring","appearance":"dark","theme":"plum","isDefault":true,` +
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
