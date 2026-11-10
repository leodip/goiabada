package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

// GetAllBrands retrieves every brand, sorted by name, the default marked.
func (c *AuthServerClient) GetAllBrands(ctx context.Context, accessToken string) ([]api.BrandResponse, error) {
	response, err := execute[api.GetBrandsResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/brands", c.baseURL),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.Brands, nil
}

// CreateBrand creates a brand from its name, appearance and theme.
func (c *AuthServerClient) CreateBrand(ctx context.Context, accessToken string, request *api.CreateBrandRequest) (*api.BrandResponse, error) {
	response, err := execute[api.CreateBrandResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/brands", c.baseURL),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusCreated,
	})
	if err != nil {
		return nil, err
	}
	return &response.Brand, nil
}

// GetBrandById retrieves one brand.
func (c *AuthServerClient) GetBrandById(ctx context.Context, accessToken string, brandId int64) (*api.BrandResponse, error) {
	response, err := execute[api.GetBrandResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/brands/%d", c.baseURL, brandId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Brand, nil
}

// UpdateBrand replaces a brand's name, appearance and theme.
func (c *AuthServerClient) UpdateBrand(ctx context.Context, accessToken string, brandId int64, request *api.UpdateBrandRequest) (*api.BrandResponse, error) {
	response, err := execute[api.UpdateBrandResponse](ctx, c, accessToken, apiRequest{
		method:        "PUT",
		url:           fmt.Sprintf("%s/api/v1/admin/brands/%d", c.baseURL, brandId),
		jsonBody:      request,
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Brand, nil
}

// DeleteBrand deletes a brand; the auth server refuses the default.
func (c *AuthServerClient) DeleteBrand(ctx context.Context, accessToken string, brandId int64) error {
	_, err := c.do(ctx, accessToken, apiRequest{
		method:        "DELETE",
		url:           fmt.Sprintf("%s/api/v1/admin/brands/%d", c.baseURL, brandId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	return err
}

// MakeBrandDefault makes a brand the default, the one every page is drawn in.
func (c *AuthServerClient) MakeBrandDefault(ctx context.Context, accessToken string, brandId int64) (*api.BrandResponse, error) {
	response, err := execute[api.MakeBrandDefaultResponse](ctx, c, accessToken, apiRequest{
		method:        "POST",
		url:           fmt.Sprintf("%s/api/v1/admin/brands/%d/make-default", c.baseURL, brandId),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return &response.Brand, nil
}

// GetBrandThemes retrieves the built-in themes in display order, with their light and dark
// palettes, which the Branding pages draw their swatches from.
func (c *AuthServerClient) GetBrandThemes(ctx context.Context, accessToken string) ([]api.BrandThemeResponse, error) {
	response, err := execute[api.GetBrandThemesResponse](ctx, c, accessToken, apiRequest{
		method:        "GET",
		url:           fmt.Sprintf("%s/api/v1/admin/brand-themes", c.baseURL),
		contentType:   contentTypeJSON,
		successStatus: http.StatusOK,
	})
	if err != nil {
		return nil, err
	}
	return response.BrandThemes, nil
}
