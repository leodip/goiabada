package datatests

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's support contact and footer links in storage (#814 decision 8): three text columns and
// one column holding the whole list of links as JSON text, read and written whole with the brand.

// Values at the widths the admin API will allow: a 254-character address, a 256-character URL, a
// "+" and 15 digits, and labels of 40 characters, some outside the Basic Multilingual Plane.
var (
	longSupportEmail = strings.Repeat("a", 64) + "@" + strings.Repeat("b", 185) + ".com"
	longURL          = "https://example.com/" + strings.Repeat("p", 236)
	longPhone        = "+123456789012345"
	longLabel        = strings.Repeat("é", 38) + "🔒!"
)

// threeFooterLinks are three links with a label in each built-in language on each.
func threeFooterLinks() record.BrandFooterLinks {
	return record.BrandFooterLinks{
		{
			URL:   "https://example.com/privacy",
			Label: "Privacy",
			Labels: map[string]string{
				"de": "Datenschutz", "en": "Privacy", "es": "Privacidad",
				"fr": "Confidentialité", "id": "Privasi", "it": "Riservatezza",
				"pl": "Prywatność", "pt-BR": "Privacidade", "ru": "Конфиденциальность", "ja": "プライバシー",
			},
		},
		{
			URL:   longURL,
			Label: longLabel,
			Labels: map[string]string{
				"de": longLabel, "en": longLabel, "es": longLabel,
				"fr": longLabel, "id": longLabel, "it": longLabel, "pl": longLabel, "pt-BR": longLabel, "ru": longLabel, "ja": longLabel,
			},
		},
		{
			URL:   "https://status.example.com",
			Label: "Status & \"uptime\"",
			Labels: map[string]string{
				"de": "Status", "en": "Status", "es": "Estado",
				"fr": "État", "id": "Status", "it": "Stato", "pl": "Status", "pt-BR": "Situação", "ru": "Статус", "ja": "ステータス",
			},
		},
	}
}

// The fixture keeps up with the catalogs, so the round trip below covers a label in every
// built-in language, a new one included.
func TestBrand_TheFooterFixtureLabelsEachLinkInEachBuiltInLanguage(t *testing.T) {
	for _, link := range threeFooterLinks() {
		tags := make([]string, 0, len(link.Labels))
		for tag := range link.Labels {
			tags = append(tags, tag)
		}
		assert.ElementsMatch(t, i18n.CatalogTags(), tags, "the labels of %s", link.URL)
	}
}

func TestBrand_TheContactAndFooterLinksReadBackWhatWasWritten(t *testing.T) {
	ctx := context.Background()

	brand := record.NewBrand("Brand "+fake.LetterN(16), "auto", "blueberry")
	brand.SupportEmail = longSupportEmail
	brand.SupportURL = longURL
	brand.SupportPhone = longPhone
	brand.FooterLinks = threeFooterLinks()
	require.NoError(t, database.CreateBrand(ctx, nil, &brand))

	stored, err := database.GetBrandByID(ctx, nil, brand.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, longSupportEmail, stored.SupportEmail, "the support email at its 254 characters")
	assert.Equal(t, longURL, stored.SupportURL, "the support page at its 256 characters")
	assert.Equal(t, longPhone, stored.SupportPhone, "the support phone, a + and 15 digits")
	assert.Equal(t, threeFooterLinks(), stored.FooterLinks, "three links, in order, with every label")

	all, err := database.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	var listed *record.Brand
	for i := range all {
		if all[i].ID == brand.ID {
			listed = &all[i]
		}
	}
	require.NotNil(t, listed, "the brand is listed")
	assert.Equal(t, threeFooterLinks(), listed.FooterLinks, "the list reads the links as the single read does")
	assert.Equal(t, longSupportEmail, listed.SupportEmail)

	// An update writes the links and the contact whole: the links reordered and cut to two, one
	// with no language label, and the contact down to a phone number.
	edit := *stored
	edit.SupportEmail = ""
	edit.SupportURL = ""
	edit.SupportPhone = "+5511999990000"
	edit.FooterLinks = record.BrandFooterLinks{
		{URL: "https://status.example.com", Label: "Status"},
		{URL: "https://example.com/privacy", Label: "Privacy", Labels: map[string]string{"pt-BR": "Privacidade"}},
	}
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))

	updated, err := database.GetBrandByID(ctx, nil, brand.ID)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Empty(t, updated.SupportEmail)
	assert.Empty(t, updated.SupportURL)
	assert.Equal(t, "+5511999990000", updated.SupportPhone)
	assert.Equal(t, record.BrandFooterLinks{
		{URL: "https://status.example.com", Label: "Status"},
		{URL: "https://example.com/privacy", Label: "Privacy", Labels: map[string]string{"pt-BR": "Privacidade"}},
	}, updated.FooterLinks)

	// And an update with no links leaves none.
	edit = *updated
	edit.FooterLinks = nil
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))
	cleared, err := database.GetBrandByID(ctx, nil, brand.ID)
	require.NoError(t, err)
	require.NotNil(t, cleared)
	assert.Nil(t, cleared.FooterLinks, "a brand saved with no links reads with none")
	assert.Equal(t, "+5511999990000", cleared.SupportPhone)
}

// A brand written with no links stores the empty list, the value migration 000092 gives every
// existing brand, and not some other spelling of nothing.
func TestBrand_NoLinksAreStoredAsTheEmptyList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := migratedIsolatedDB(t)

	brand := record.NewBrand("No links", "auto", "blueberry")
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &brand))

	var stored string
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf("SELECT footer_links FROM brands WHERE id = %d", brand.ID)).Scan(&stored))
	assert.Equalf(t, "[]", stored, "a brand with no links on %s", dbType())
}

// The engine cannot check the text's shape, so a stored value that is not a list of links reads as
// no links, logged, and the brand is still read: its page is drawn without a footer link rather than
// not at all (#814 decision 8).
func TestBrand_AStoredLinksValueThatDoesNotParseReadsAsNone(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	_, setupErr := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET support_email = 'help@example.com' WHERE id = %d", def.ID))
	require.NoError(t, setupErr)

	for _, stored := range []string{
		"not json",
		"",
		`[{"url":"https://example.com/privacy","label":"Privacy"}`,
		`{"url":"https://example.com/privacy","label":"Privacy"}`,
		`[1, 2]`,
		`[{"url":"https://example.com/privacy","label":7}]`,
		`[{"url":"https://example.com/privacy","label":"Privacy","labels":["de"]}]`,
		`[{"url":"https://example.com/privacy"}]`,
		`[{"label":"Privacy"}]`,
		`[{"url":"https://example.com/privacy","label":"Privacy"},{"url":"","label":"Status"}]`,
	} {
		_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET footer_links = '%s' WHERE id = %d", stored, def.ID))
		require.NoErrorf(t, err, "store %q on %s", stored, dbType())

		capture := logtest.CaptureSlog(t)

		byID, err := h.DB.GetBrandByID(ctx, nil, def.ID)
		require.NoErrorf(t, err, "%q: the brand is still read on %s", stored, dbType())
		require.NotNil(t, byID)
		assert.Nilf(t, byID.FooterLinks, "%q reads as no links on %s", stored, dbType())
		assert.Equalf(t, "help@example.com", byID.SupportEmail, "%q: the rest of the brand is read on %s", stored, dbType())
		assert.Equal(t, "Default", byID.Name)

		byDefault, err := h.DB.GetDefaultBrand(ctx, nil)
		require.NoErrorf(t, err, "%q: the default brand is still read on %s", stored, dbType())
		require.NotNil(t, byDefault)
		assert.Nilf(t, byDefault.FooterLinks, "%q reads as no links on %s", stored, dbType())

		all, err := h.DB.GetAllBrands(ctx, nil)
		require.NoErrorf(t, err, "%q: the list is still read on %s", stored, dbType())
		require.Len(t, all, 1)
		assert.Nilf(t, all[0].FooterLinks, "%q reads as no links on %s", stored, dbType())

		var logged []logtest.CapturedRecord
		for _, r := range capture.Records() {
			if r.Message == "brand footer links do not parse and are read as none" {
				logged = append(logged, r)
			}
		}
		require.Lenf(t, logged, 3, "%q: each of the three reads logs it on %s", stored, dbType())
		for _, r := range logged {
			assert.Equal(t, slog.LevelWarn, r.Level)
			assert.Equal(t, def.ID, r.Attrs["brand_id"], "the record names the brand")
			assert.NotEmpty(t, r.Attrs["error"], "the record carries why")
		}
	}

	// A well-formed list reads as itself again, and logs nothing.
	_, err := h.SQL.Exec(fmt.Sprintf(`UPDATE brands SET footer_links = '[{"url":"https://example.com/privacy","label":"Privacy"}]' WHERE id = %d`, def.ID))
	require.NoError(t, err)
	capture := logtest.CaptureSlog(t)
	byID, err := h.DB.GetBrandByID(ctx, nil, def.ID)
	require.NoError(t, err)
	require.NotNil(t, byID)
	assert.Equal(t, record.BrandFooterLinks{{URL: "https://example.com/privacy", Label: "Privacy"}}, byID.FooterLinks)
	for _, r := range capture.Records() {
		assert.NotEqual(t, "brand footer links do not parse and are read as none", r.Message)
	}
}
