package apimapping

import (
	"maps"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// ToBrandResponse answers a brand, isDefault saying whether the settings row points at it.
func ToBrandResponse(brand *record.Brand, isDefault bool) api.BrandResponse {
	resp := api.BrandResponse{
		Id:         brand.Id,
		Name:       brand.Name,
		Appearance: string(brand.Appearance),
		Theme:      brand.Theme,
		IsDefault:  isDefault,
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
