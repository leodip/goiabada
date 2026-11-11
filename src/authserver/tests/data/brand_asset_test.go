package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Brand assets in storage, and a brand's kit: its four choices and the six slots that point into
// the assets (#813 decision 2).
//
// An asset's own reads and a brand's kit run on the tier's shared database. The sweep deletes every
// unattached asset older than its cutoff, whoever wrote it, so it runs on an isolated database.

// brandAssetBytes is an asset's content in these tests: a PNG signature, then a NUL, every byte
// value from 0x80 up and a trailing zero, so a column that is not binary-safe, or one that trims or
// pads, reads back something else.
func brandAssetBytes(tag string) []byte {
	content := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
	for b := 0x80; b <= 0xff; b++ {
		content = append(content, byte(b))
	}
	content = append(content, []byte(tag)...)
	return append(content, 0x00)
}

// createTestBrandAsset stores a small asset of the kind on db and answers it as the create left it.
func createTestBrandAsset(t *testing.T, db data.Database, kind record.BrandAssetKind) *record.BrandAsset {
	t.Helper()
	asset := &record.BrandAsset{
		Kind:        kind,
		ContentType: "image/png",
		Fingerprint: fake.LetterN(12),
		Width:       40,
		Height:      20,
		Content:     brandAssetBytes(fake.LetterN(8)),
	}
	require.NoError(t, db.CreateBrandAsset(context.Background(), nil, asset))
	require.Positive(t, asset.Id, "the create answers the asset's id")
	return asset
}

func TestCreateBrandAsset_ReadsBackWithItsBytes(t *testing.T) {
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Minute)

	for _, c := range []struct {
		kind          record.BrandAssetKind
		contentType   string
		width, height int
	}{
		{"logo", "image/png", 512, 10},
		{"favicon", "image/png", 48, 48},
		{"background", "image/jpeg", 3840, 2160},
		{"font", "font/woff2", 0, 0},
	} {
		content := brandAssetBytes(string(c.kind))
		asset := &record.BrandAsset{
			Kind:        c.kind,
			ContentType: c.contentType,
			Fingerprint: "a1b2c3d4e5f6",
			Width:       c.width,
			Height:      c.height,
			Content:     content,
		}
		require.NoError(t, database.CreateBrandAsset(ctx, nil, asset))
		require.Positivef(t, asset.Id, "the create answers the %s's id", c.kind)

		stored, err := database.GetBrandAssetById(ctx, nil, asset.Id)
		require.NoError(t, err)
		require.NotNilf(t, stored, "the %s %d reads back", c.kind, asset.Id)
		assert.Equal(t, asset.Id, stored.Id)
		assert.Equal(t, c.kind, stored.Kind)
		assert.Equal(t, c.contentType, stored.ContentType)
		assert.Equal(t, "a1b2c3d4e5f6", stored.Fingerprint)
		assert.Equal(t, c.width, stored.Width)
		assert.Equal(t, c.height, stored.Height)
		assert.Truef(t, bytes.Equal(content, stored.Content), "the %s's bytes read back unchanged: %d bytes stored, %d read",
			c.kind, len(content), len(stored.Content))
		assert.Truef(t, stored.CreatedAt.After(before), "created_at is the time of the create, read %v", stored.CreatedAt)
	}
}

// The largest asset decision 3 lets in is 2 MiB, a background or a font: the column holds it.
func TestCreateBrandAsset_HoldsTwoMebibytes(t *testing.T) {
	ctx := context.Background()
	content := bytes.Repeat([]byte{0x00, 0xff, 0x7f, 0x80}, 2*1024*1024/4)
	asset := &record.BrandAsset{Kind: "background", ContentType: "image/webp", Fingerprint: "ffffffffffff",
		Width: 3840, Height: 3840, Content: content}
	require.NoError(t, database.CreateBrandAsset(ctx, nil, asset))

	stored, err := database.GetBrandAssetById(ctx, nil, asset.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Len(t, stored.Content, 2*1024*1024)
	assert.True(t, bytes.Equal(content, stored.Content), "a 2 MiB asset reads back unchanged")
}

func TestGetBrandAssetById_AnUnknownIdIsNil(t *testing.T) {
	stored, err := database.GetBrandAssetById(context.Background(), nil, 987_654_321)
	require.NoError(t, err)
	assert.Nil(t, stored)
}

// GetBrandAssetsByIds answers what GetBrandAssetById does but the bytes, which it leaves out: a
// brand's answer and its pages read their assets through it (decision 2).
func TestGetBrandAssetsByIds_AnswersEveryAssetNamedWithoutItsBytes(t *testing.T) {
	ctx := context.Background()
	logo := createTestBrandAsset(t, database, "logo")
	font := &record.BrandAsset{Kind: "font", ContentType: "font/woff2", Fingerprint: "0123456789ab",
		Content: []byte("wOF2" + fake.LetterN(8))}
	require.NoError(t, database.CreateBrandAsset(ctx, nil, font))

	assets, err := database.GetBrandAssetsByIds(ctx, nil, []int64{font.Id, 987_654_321, logo.Id, font.Id})
	require.NoError(t, err)
	require.Len(t, assets, 2, "each asset named once, and none for the id naming none")
	byId := map[int64]record.BrandAsset{}
	for _, a := range assets {
		byId[a.Id] = a
	}

	gotLogo, ok := byId[logo.Id]
	require.True(t, ok, "the logo is answered")
	assert.Equal(t, record.BrandAssetKind("logo"), gotLogo.Kind)
	assert.Equal(t, "image/png", gotLogo.ContentType)
	assert.Equal(t, logo.Fingerprint, gotLogo.Fingerprint)
	assert.Equal(t, 40, gotLogo.Width)
	assert.Equal(t, 20, gotLogo.Height)
	assert.True(t, logo.CreatedAt.Equal(gotLogo.CreatedAt) || gotLogo.CreatedAt.Sub(logo.CreatedAt).Abs() < time.Millisecond,
		"created_at reads back: wrote %v, read %v", logo.CreatedAt, gotLogo.CreatedAt)
	assert.Nil(t, gotLogo.Content, "the bytes are left out")

	gotFont, ok := byId[font.Id]
	require.True(t, ok, "the font is answered")
	assert.Equal(t, record.BrandAssetKind("font"), gotFont.Kind)
	assert.Equal(t, "font/woff2", gotFont.ContentType)
	assert.Equal(t, "0123456789ab", gotFont.Fingerprint)
	assert.Equal(t, 0, gotFont.Width)
	assert.Equal(t, 0, gotFont.Height)
	assert.Nil(t, gotFont.Content, "the bytes are left out")

	none, err := database.GetBrandAssetsByIds(ctx, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, none, "no ids, no assets")
}

// brandKitAssets is one stored asset for each of a brand's six slots, of the slot's kind.
type brandKitAssets struct {
	logo, darkLogo, favicon, background, regularFont, boldFont *record.BrandAsset
}

func createBrandKitAssets(t *testing.T, db data.Database) brandKitAssets {
	t.Helper()
	return brandKitAssets{
		logo:        createTestBrandAsset(t, db, "logo"),
		darkLogo:    createTestBrandAsset(t, db, "logo"),
		favicon:     createTestBrandAsset(t, db, "favicon"),
		background:  createTestBrandAsset(t, db, "background"),
		regularFont: createTestBrandAsset(t, db, "font"),
		boldFont:    createTestBrandAsset(t, db, "font"),
	}
}

func brandSlot(asset *record.BrandAsset) sql.NullInt64 {
	return sql.NullInt64{Int64: asset.Id, Valid: true}
}

// assertBrandKit holds a brand read back to the kit written, field by field.
func assertBrandKit(t *testing.T, want, got *record.Brand, phase string) {
	t.Helper()
	assert.Equalf(t, want.Corners, got.Corners, "[%s] corners", phase)
	assert.Equalf(t, want.Font, got.Font, "[%s] font", phase)
	assert.Equalf(t, want.BackgroundFit, got.BackgroundFit, "[%s] background fit", phase)
	assert.Equalf(t, want.HideAppName, got.HideAppName, "[%s] hide app name", phase)
	assert.Equalf(t, want.LogoAssetId, got.LogoAssetId, "[%s] logo slot", phase)
	assert.Equalf(t, want.DarkLogoAssetId, got.DarkLogoAssetId, "[%s] dark logo slot", phase)
	assert.Equalf(t, want.FaviconAssetId, got.FaviconAssetId, "[%s] favicon slot", phase)
	assert.Equalf(t, want.BackgroundAssetId, got.BackgroundAssetId, "[%s] background slot", phase)
	assert.Equalf(t, want.RegularFontAssetId, got.RegularFontAssetId, "[%s] regular font slot", phase)
	assert.Equalf(t, want.BoldFontAssetId, got.BoldFontAssetId, "[%s] bold font slot", phase)
}

// A brand is written and read with its four choices and its six slots, each slot its own column:
// every slot names a different asset, so two swapped slots read back wrong.
func TestBrand_ReadsAndWritesItsKit(t *testing.T) {
	ctx := context.Background()
	assets := createBrandKitAssets(t, database)

	brand := &record.Brand{
		Name: "Kit " + fake.LetterN(16), Appearance: "light", Theme: "plum",
		Corners: "pill", Font: "uploaded", BackgroundFit: "tile", HideAppName: true,
		LogoAssetId: brandSlot(assets.logo), DarkLogoAssetId: brandSlot(assets.darkLogo),
		FaviconAssetId: brandSlot(assets.favicon), BackgroundAssetId: brandSlot(assets.background),
		RegularFontAssetId: brandSlot(assets.regularFont), BoldFontAssetId: brandSlot(assets.boldFont),
	}
	require.NoError(t, database.CreateBrand(ctx, nil, brand))

	stored, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assertBrandKit(t, brand, stored, "created, by id")

	all, err := database.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	var listed *record.Brand
	for i := range all {
		if all[i].Id == brand.Id {
			listed = &all[i]
		}
	}
	require.NotNil(t, listed, "the brand is listed")
	assertBrandKit(t, brand, listed, "created, listed")

	// Every choice changed, two slots emptied, two moved to other assets, two kept.
	newLogo := createTestBrandAsset(t, database, "logo")
	newBackground := createTestBrandAsset(t, database, "background")
	edit := *stored
	edit.Corners, edit.Font, edit.BackgroundFit, edit.HideAppName = "square", "neo-grotesque", "contain", false
	edit.LogoAssetId = brandSlot(newLogo)
	edit.DarkLogoAssetId = sql.NullInt64{}
	edit.BackgroundAssetId = brandSlot(newBackground)
	edit.BoldFontAssetId = sql.NullInt64{}
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))

	updated, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assertBrandKit(t, &edit, updated, "updated")
	assert.Equal(t, sql.NullInt64{Int64: assets.favicon.Id, Valid: true}, updated.FaviconAssetId, "a kept slot is kept")
	assert.Equal(t, brand.Name, updated.Name)
	assert.Equal(t, record.BrandAppearance("light"), updated.Appearance)
	assert.Equal(t, "plum", updated.Theme)
}

// Each value of each choice reads back as written.
func TestBrand_EveryChoiceReadsBack(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		corners record.BrandCorners
		font    record.BrandFont
		fit     record.BrandBackgroundFit
	}{
		{"square", "system-ui", "cover"},
		{"rounded", "humanist", "contain"},
		{"pill", "geometric", "tile"},
		{"rounded", "serif", "cover"},
		{"square", "neo-grotesque", "contain"},
		{"pill", "rounded", "tile"},
		{"rounded", "uploaded", "cover"},
	} {
		brand := &record.Brand{Name: "Choice " + fake.LetterN(16), Appearance: "auto", Theme: "blueberry",
			Corners: c.corners, Font: c.font, BackgroundFit: c.fit}
		require.NoError(t, database.CreateBrand(ctx, nil, brand))
		stored, err := database.GetBrandById(ctx, nil, brand.Id)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assertBrandKit(t, brand, stored, fmt.Sprintf("%s, %s, %s", c.corners, c.font, c.fit))
	}
}

// A slot is a foreign key: the engine refuses one naming no asset, on a create and on an update,
// and the brand is left as it was.
func TestBrand_ASlotNamingNoAssetIsRefused(t *testing.T) {
	ctx := context.Background()
	missing := sql.NullInt64{Int64: 987_654_321, Valid: true}

	for _, set := range []struct {
		name string
		fill func(*record.Brand)
	}{
		{"logo", func(b *record.Brand) { b.LogoAssetId = missing }},
		{"dark logo", func(b *record.Brand) { b.DarkLogoAssetId = missing }},
		{"favicon", func(b *record.Brand) { b.FaviconAssetId = missing }},
		{"background", func(b *record.Brand) { b.BackgroundAssetId = missing }},
		{"regular font", func(b *record.Brand) { b.RegularFontAssetId = missing }},
		{"bold font", func(b *record.Brand) { b.BoldFontAssetId = missing }},
	} {
		created := record.NewBrand("Missing "+fake.LetterN(16), "auto", "blueberry")
		set.fill(&created)
		require.Errorf(t, database.CreateBrand(ctx, nil, &created), "a create whose %s slot names no asset", set.name)

		existing := record.NewBrand("Existing "+fake.LetterN(16), "auto", "blueberry")
		require.NoError(t, database.CreateBrand(ctx, nil, &existing))
		edit := existing
		set.fill(&edit)
		require.Errorf(t, database.UpdateBrand(ctx, nil, &edit), "an update whose %s slot names no asset", set.name)
		stored, err := database.GetBrandById(ctx, nil, existing.Id)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assertBrandKit(t, &existing, stored, "after the refused "+set.name+" update")
	}
}

// NewBrand is a brand drawn as one was before the kit: rounded, System UI, cover, the name shown,
// every slot empty, which is what migration 000091 gives every existing brand.
func TestNewBrand_IsDrawnAsBeforeTheKit(t *testing.T) {
	ctx := context.Background()
	brand := record.NewBrand("New "+fake.LetterN(16), "dark", "avocado")
	require.NoError(t, database.CreateBrand(ctx, nil, &brand))

	stored, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, record.BrandAppearance("dark"), stored.Appearance)
	assert.Equal(t, "avocado", stored.Theme)
	assertBrandKit(t, &record.Brand{Corners: "rounded", Font: "system-ui", BackgroundFit: "cover"}, stored, "a new brand")
}

// The default brand is read with its kit, through the join on the settings row.
func TestGetDefaultBrand_ReadsTheKit(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	assets := createBrandKitAssets(t, h.DB)

	def.Corners, def.Font, def.BackgroundFit, def.HideAppName = "pill", "serif", "contain", true
	def.LogoAssetId, def.DarkLogoAssetId = brandSlot(assets.logo), brandSlot(assets.darkLogo)
	def.FaviconAssetId, def.BackgroundAssetId = brandSlot(assets.favicon), brandSlot(assets.background)
	def.RegularFontAssetId, def.BoldFontAssetId = brandSlot(assets.regularFont), brandSlot(assets.boldFont)
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, def))

	got, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, got)
	assertBrandKit(t, def, got, "the default brand")
}

// The sweep deletes an asset no slot names once it is older than the cutoff, and nothing else: not
// a newer unattached asset, and not an old asset any one of the six slots names. An asset a slot
// stops naming, by a replace or a removal, and the assets of a deleted brand, are unattached and
// swept (decision 2). It answers how many it deleted.
func TestDeleteUnattachedBrandAssets_DeletesOnlyOldUnattachedAssets(t *testing.T) {
	ctx := context.Background()
	h, _ := brandsIsolatedDB(t)

	// Created before the cutoff.
	unattached := createTestBrandAsset(t, h.DB, "background")
	attached := createBrandKitAssets(t, h.DB)
	replaced := createTestBrandAsset(t, h.DB, "logo")
	removed := createTestBrandAsset(t, h.DB, "favicon")
	ofDeletedBrand := createTestBrandAsset(t, h.DB, "font")

	keeper := record.NewBrand("Keeper", "auto", "blueberry")
	keeper.LogoAssetId, keeper.DarkLogoAssetId = brandSlot(attached.logo), brandSlot(attached.darkLogo)
	keeper.FaviconAssetId, keeper.BackgroundAssetId = brandSlot(attached.favicon), brandSlot(attached.background)
	keeper.RegularFontAssetId, keeper.BoldFontAssetId = brandSlot(attached.regularFont), brandSlot(attached.boldFont)
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &keeper))

	editor := record.NewBrand("Editor", "auto", "blueberry")
	editor.LogoAssetId, editor.FaviconAssetId = brandSlot(replaced), brandSlot(removed)
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &editor))

	doomed := record.NewBrand("Doomed", "auto", "blueberry")
	doomed.RegularFontAssetId = brandSlot(ofDeletedBrand)
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &doomed))

	time.Sleep(20 * time.Millisecond)
	cutoff := time.Now().UTC()
	time.Sleep(20 * time.Millisecond)

	// Created after the cutoff.
	recent := createTestBrandAsset(t, h.DB, "logo")
	replacement := createTestBrandAsset(t, h.DB, "logo")

	// Nothing unattached is old yet but the one never attached.
	deleted, err := h.DB.DeleteUnattachedBrandAssets(ctx, nil, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted, "only the asset never attached is swept before any slot lets go")
	assertBrandAssetStored(t, h, unattached, false, "an old asset never attached")

	// The editor replaces its logo and removes its favicon; the doomed brand is deleted.
	editor.LogoAssetId = brandSlot(replacement)
	editor.FaviconAssetId = sql.NullInt64{}
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, &editor))
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		_, deleteErr := h.DB.DeleteBrand(ctx, tx, doomed.Id)
		return deleteErr
	}))

	deleted, err = h.DB.DeleteUnattachedBrandAssets(ctx, nil, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 3, deleted, "the replaced, the removed and the deleted brand's asset")

	assertBrandAssetStored(t, h, replaced, false, "an old asset its slot was moved off")
	assertBrandAssetStored(t, h, removed, false, "an old asset its slot was emptied of")
	assertBrandAssetStored(t, h, ofDeletedBrand, false, "an old asset of a deleted brand")
	for name, asset := range map[string]*record.BrandAsset{
		"logo": attached.logo, "dark logo": attached.darkLogo, "favicon": attached.favicon,
		"background": attached.background, "regular font": attached.regularFont, "bold font": attached.boldFont,
	} {
		assertBrandAssetStored(t, h, asset, true, "an old asset in the "+name+" slot")
	}
	assertBrandAssetStored(t, h, recent, true, "a newer unattached asset")
	assertBrandAssetStored(t, h, replacement, true, "a newer attached asset")

	deleted, err = h.DB.DeleteUnattachedBrandAssets(ctx, nil, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted, "a second sweep finds nothing")
	assert.Equalf(t, 8, count000062(t, h, "brand_assets"), "six attached, one newer unattached, one newer attached on %s", dbType())
}

func assertBrandAssetStored(t *testing.T, h *isolatedDB, asset *record.BrandAsset, want bool, what string) {
	t.Helper()
	stored, err := h.DB.GetBrandAssetById(context.Background(), nil, asset.Id)
	require.NoError(t, err)
	if want {
		assert.NotNilf(t, stored, "%s is kept on %s", what, dbType())
	} else {
		assert.Nilf(t, stored, "%s is swept on %s", what, dbType())
	}
}
