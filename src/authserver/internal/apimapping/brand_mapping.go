package apimapping

import (
	"maps"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// ToBrandResponse answers a brand with its kit's choices, its footer links and support contact, and
// its six slots, slots being the assets they name, each answered as ToBrandAssetResponse answers it
// and null for an empty slot; isDefault says whether the settings row points at the brand and
// clientCount how many clients are drawn in it.
func ToBrandResponse(brand *record.Brand, slots brandasset.Slots, baseURL string, isDefault bool, clientCount int) api.BrandResponse {
	slot := func(asset *record.BrandAsset) *api.BrandAssetResponse {
		if asset == nil {
			return nil
		}
		answer := ToBrandAssetResponse(asset, baseURL)
		return &answer
	}
	resp := api.BrandResponse{
		Id:            brand.Id,
		Name:          brand.Name,
		Appearance:    string(brand.Appearance),
		Theme:         brand.Theme,
		Corners:       string(brand.Corners),
		Font:          string(brand.Font),
		BackgroundFit: string(brand.BackgroundFit),
		HideAppName:   brand.HideAppName,
		Logo:          slot(slots.Logo),
		DarkLogo:      slot(slots.DarkLogo),
		Favicon:       slot(slots.Favicon),
		Background:    slot(slots.Background),
		RegularFont:   slot(slots.RegularFont),
		BoldFont:      slot(slots.BoldFont),
		FooterLinks:   ToBrandFooterLinkResponses(brand.FooterLinks),
		SupportEmail:  brand.SupportEmail,
		SupportUrl:    brand.SupportURL,
		SupportPhone:  brand.SupportPhone,
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

// ToBrandFooterLinkResponses answers a brand's footer links in order, [] for none, each link's
// labels a copy and {} when it has none, so a link read and sent back is the same link (#814
// decision 9).
func ToBrandFooterLinkResponses(links record.BrandFooterLinks) []api.BrandFooterLinkResponse {
	responses := make([]api.BrandFooterLinkResponse, 0, len(links))
	for _, link := range links {
		labels := maps.Clone(link.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		responses = append(responses, api.BrandFooterLinkResponse{Url: link.URL, Label: link.Label, Labels: labels})
	}
	return responses
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
