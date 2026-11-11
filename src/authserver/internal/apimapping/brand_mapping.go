package apimapping

import (
	"maps"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// ToBrandResponse answers a brand with its kit's choices, isDefault saying whether the settings row
// points at it and clientCount how many clients are drawn in it.
func ToBrandResponse(brand *record.Brand, isDefault bool, clientCount int) api.BrandResponse {
	resp := api.BrandResponse{
		Id:            brand.Id,
		Name:          brand.Name,
		Appearance:    string(brand.Appearance),
		Theme:         brand.Theme,
		Corners:       string(brand.Corners),
		Font:          string(brand.Font),
		BackgroundFit: string(brand.BackgroundFit),
		HideAppName:   brand.HideAppName,
		IsDefault:     isDefault,
		ClientCount:   clientCount,
	}
	if brand.CreatedAt.Valid {
		createdAt := brand.CreatedAt.Time
		resp.CreatedAt = &createdAt
	}
	if brand.UpdatedAt.Valid {
		updatedAt := brand.UpdatedAt.Time
		resp.UpdatedAt = &updatedAt
	}
	return resp
}

// ToBrandThemeResponses answers the built-in themes in the order given, each palette a copy.
func ToBrandThemeResponses(presets []brandthemes.Preset) []api.BrandThemeResponse {
	responses := make([]api.BrandThemeResponse, 0, len(presets))
	for _, preset := range presets {
		responses = append(responses, api.BrandThemeResponse{
			Key:   preset.Key,
			Light: maps.Clone(map[string]string(preset.Light)),
			Dark:  maps.Clone(map[string]string(preset.Dark)),
		})
	}
	return responses
}

// ToBrandAssetResponse answers an asset without its bytes, its URL the path it is served at made
// absolute on baseURL.
func ToBrandAssetResponse(asset *record.BrandAsset, baseURL string) api.BrandAssetResponse {
	return api.BrandAssetResponse{
		Id:          asset.Id,
		Kind:        string(asset.Kind),
		Url:         baseURL + brandasset.Path(asset),
		ContentType: asset.ContentType,
		Width:       asset.Width,
		Height:      asset.Height,
	}
}
