package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Brands in storage, with the settings row's pointer to the default brand (#810 decision 1).
//
// A brand's own reads and writes run on the tier's shared database, under names unique to the run.
// The default pointer lives on settings row 1, which the shared database's other tests write as
// they like, so everything about the pointer runs on an isolated database seeded with that row.

// createTestBrand writes a brand under a name no other draw meets, inside the column's 60
// characters.
func createTestBrand(t *testing.T, appearance record.BrandAppearance, theme string) *record.Brand {
	t.Helper()
	brand := &record.Brand{
		Name:       "Brand " + fake.LetterN(16),
		Appearance: appearance,
		Theme:      theme,
	}
	require.NoError(t, database.CreateBrand(context.Background(), nil, brand))
	return brand
}

func TestCreateBrand_ReadsBackWhatWasWritten(t *testing.T) {
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Minute)

	for _, c := range []struct {
		appearance record.BrandAppearance
		theme      string
	}{
		{"auto", "blueberry"}, {"light", "plum"}, {"dark", "high-contrast"},
	} {
		brand := &record.Brand{Name: "Brand " + fake.LetterN(16), Appearance: c.appearance, Theme: c.theme}
		require.NoError(t, database.CreateBrand(ctx, nil, brand))
		require.Positive(t, brand.Id, "the create answers the brand's id")

		stored, err := database.GetBrandById(ctx, nil, brand.Id)
		require.NoError(t, err)
		require.NotNilf(t, stored, "the brand %d reads back", brand.Id)
		assert.Equal(t, brand.Name, stored.Name)
		assert.Equal(t, c.appearance, stored.Appearance)
		assert.Equal(t, c.theme, stored.Theme)
		require.True(t, stored.CreatedAt.Valid, "created_at is stamped")
		require.True(t, stored.UpdatedAt.Valid, "updated_at is stamped")
		assert.True(t, stored.CreatedAt.Time.After(before), "created_at is the time of the create")
	}
}

func TestGetBrandById_AnUnknownIdIsNil(t *testing.T) {
	stored, err := database.GetBrandById(context.Background(), nil, 987_654_321)
	require.NoError(t, err)
	assert.Nil(t, stored)
}

func TestUpdateBrand_WritesNameAppearanceAndThemeAndKeepsCreatedAt(t *testing.T) {
	ctx := context.Background()
	brand := createTestBrand(t, "auto", "blueberry")
	created, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, created)

	time.Sleep(10 * time.Millisecond)
	renamed := "Renamed " + fake.LetterN(16)
	edit := &record.Brand{
		Id:         brand.Id,
		CreatedAt:  sql.NullTime{Time: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
		Name:       renamed,
		Appearance: "dark",
		Theme:      "avocado",
	}
	require.NoError(t, database.UpdateBrand(ctx, nil, edit))

	stored, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, renamed, stored.Name)
	assert.Equal(t, record.BrandAppearance("dark"), stored.Appearance)
	assert.Equal(t, "avocado", stored.Theme)
	assert.True(t, created.CreatedAt.Time.Equal(stored.CreatedAt.Time),
		"created_at is not written by an update: was %v, now %v", created.CreatedAt.Time, stored.CreatedAt.Time)
	assert.True(t, stored.UpdatedAt.Time.After(created.UpdatedAt.Time), "updated_at moves on an update")

	require.Error(t, database.UpdateBrand(ctx, nil, &record.Brand{Name: "No id"}), "an update with no id")
}

func TestGetAllBrands_AnswersEveryBrandInIdOrder(t *testing.T) {
	ctx := context.Background()
	first := createTestBrand(t, "light", "guava")
	second := createTestBrand(t, "dark", "coconut")

	brands, err := database.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	var firstAt, secondAt = -1, -1
	for i, b := range brands {
		if i > 0 {
			assert.Less(t, brands[i-1].Id, b.Id, "the list is in id order")
		}
		switch b.Id {
		case first.Id:
			firstAt = i
			assert.Equal(t, first.Name, b.Name)
			assert.Equal(t, record.BrandAppearance("light"), b.Appearance)
			assert.Equal(t, "guava", b.Theme)
		case second.Id:
			secondAt = i
		}
	}
	assert.GreaterOrEqual(t, firstAt, 0, "the first brand is listed")
	assert.Greater(t, secondAt, firstAt, "the second brand is listed after the first")
}

// A name is unique among brands, compared exactly: a create or a rename to a name another brand
// holds is refused with the unique violation the API turns into name_in_use, and a name differing
// only by case is another name.
func TestBrand_TheNameIsUnique(t *testing.T) {
	ctx := context.Background()
	existing := createTestBrand(t, "auto", "blueberry")

	err := database.CreateBrand(ctx, nil, &record.Brand{Name: existing.Name, Appearance: "dark", Theme: "plum"})
	require.Error(t, err, "a second brand of one name")
	require.ErrorIs(t, err, data.ErrUniqueViolation)

	other := createTestBrand(t, "auto", "blueberry")
	other.Name = existing.Name
	err = database.UpdateBrand(ctx, nil, other)
	require.Error(t, err, "a rename to a name another brand holds")
	require.ErrorIs(t, err, data.ErrUniqueViolation)

	upper := &record.Brand{Name: "BRAND " + existing.Name[len("Brand "):], Appearance: "auto", Theme: "blueberry"}
	require.NoError(t, database.CreateBrand(ctx, nil, upper), "a name differing by case is another name")
}

// brandsIsolatedDB is a migrated isolated database holding settings row 1, pointing at a brand
// named Default, written as the first start writes them.
func brandsIsolatedDB(t *testing.T) (*isolatedDB, *record.Brand) {
	t.Helper()
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	brand := &record.Brand{Name: "Default", Appearance: "auto", Theme: "blueberry"}
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := h.DB.CreateBrand(ctx, tx, brand); err != nil {
			return err
		}
		settings := initialSettings("Brands")
		settings.DefaultBrandId = sql.NullInt64{Int64: brand.Id, Valid: true}
		return h.DB.CreateInitialSettings(ctx, tx, settings)
	}))
	return h, brand
}

// defaultBrandIdOf reads the pointer with raw SQL, a second read beside the data layer's.
func defaultBrandIdOf(t *testing.T, h *isolatedDB) sql.NullInt64 {
	t.Helper()
	var id sql.NullInt64
	require.NoErrorf(t, h.SQL.QueryRow("SELECT default_brand_id FROM settings WHERE id = 1").Scan(&id),
		"read settings.default_brand_id on %s", dbType())
	return id
}

func makeDefault(h *isolatedDB, brandId int64) (int64, error) {
	ctx := context.Background()
	var previous int64
	err := h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		previous, err = h.DB.MakeBrandDefault(ctx, tx, brandId)
		return err
	})
	return previous, err
}

func deleteBrand(h *isolatedDB, brandId int64) error {
	ctx := context.Background()
	return h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		_, err := h.DB.DeleteBrand(ctx, tx, brandId)
		return err
	})
}

// TestBrands_TheDefaultPointer holds the pointer to decision 1: the settings row names one existing
// brand, a move only puts it on another existing brand, no settings save clears or moves it, the
// default cannot be deleted, and the schema refuses deleting the brand it names.
func TestBrands_TheDefaultPointer(t *testing.T) {
	ctx := context.Background()
	h, seeded := brandsIsolatedDB(t)

	// The default is the brand the settings row names.
	def, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, def, "the default brand reads")
	assert.Equal(t, seeded.Id, def.Id)
	assert.Equal(t, "Default", def.Name)
	assert.Equal(t, record.BrandAppearance("auto"), def.Appearance)
	assert.Equal(t, "blueberry", def.Theme)
	settings, err := h.DB.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)
	assert.Equal(t, sql.NullInt64{Int64: seeded.Id, Valid: true}, settings.DefaultBrandId, "the settings row reads its pointer")

	other := &record.Brand{Name: "Other", Appearance: "dark", Theme: "plum"}
	require.NoError(t, h.DB.CreateBrand(ctx, nil, other))

	// No settings save moves or clears the pointer, whatever its copy of the row says.
	for _, written := range []sql.NullInt64{{}, {Int64: other.Id, Valid: true}} {
		settings.DefaultBrandId = written
		settings.AppName = "Saved " + fake.LetterN(6)
		require.NoError(t, h.DB.UpdateSettings(ctx, nil, settings))
		assert.Equalf(t, sql.NullInt64{Int64: seeded.Id, Valid: true}, defaultBrandIdOf(t, h),
			"a settings save carrying %v leaves the pointer", written)
	}

	// A move answers the brand it moved from.
	previous, err := makeDefault(h, other.Id)
	require.NoError(t, err)
	assert.Equal(t, seeded.Id, previous, "the move answers the old default")
	assert.Equal(t, sql.NullInt64{Int64: other.Id, Valid: true}, defaultBrandIdOf(t, h), "the pointer moved")
	def, err = h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, def)
	assert.Equal(t, other.Id, def.Id)
	assert.Equal(t, "Other", def.Name)

	// A move to the default changes nothing and says so.
	previous, err = makeDefault(h, other.Id)
	require.NoError(t, err)
	assert.Equal(t, other.Id, previous, "a move to the default answers the default itself")
	assert.Equal(t, sql.NullInt64{Int64: other.Id, Valid: true}, defaultBrandIdOf(t, h))

	// A move to a brand that is not there is refused and writes nothing.
	_, err = makeDefault(h, other.Id+1_000)
	require.ErrorIs(t, err, data.ErrBrandNotFound)
	assert.Equal(t, sql.NullInt64{Int64: other.Id, Valid: true}, defaultBrandIdOf(t, h), "a refused move leaves the pointer")

	// The default cannot be deleted.
	err = deleteBrand(h, other.Id)
	require.ErrorIs(t, err, data.ErrDefaultBrandNotDeletable)
	kept, err := h.DB.GetBrandById(ctx, nil, other.Id)
	require.NoError(t, err)
	assert.NotNil(t, kept, "the refused deletion kept the default brand")

	// Nor can the schema be made to: the foreign key refuses deleting the brand the row names.
	_, err = h.SQL.Exec(fmt.Sprintf("DELETE FROM brands WHERE id = %d", other.Id))
	require.Errorf(t, err, "the foreign key refuses deleting the default brand on %s", dbType())

	// Another brand is deleted, once.
	require.NoError(t, deleteBrand(h, seeded.Id), "the brand that is no longer the default")
	gone, err := h.DB.GetBrandById(ctx, nil, seeded.Id)
	require.NoError(t, err)
	assert.Nil(t, gone, "the brand is gone")
	require.ErrorIs(t, deleteBrand(h, seeded.Id), data.ErrBrandNotFound, "a second deletion finds nothing")

	// Both writes need a transaction, as the lock they take does.
	_, err = h.DB.MakeBrandDefault(ctx, nil, other.Id)
	require.Error(t, err, "a move without a transaction")
	_, err = h.DB.DeleteBrand(ctx, nil, other.Id)
	require.Error(t, err, "a deletion without a transaction")

	// An empty pointer reads as no default, and a move from it answers 0.
	_, err = h.SQL.Exec("UPDATE settings SET default_brand_id = NULL WHERE id = 1")
	require.NoError(t, err)
	def, err = h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, def, "an empty pointer names no brand")
	previous, err = makeDefault(h, other.Id)
	require.NoError(t, err)
	assert.Equal(t, int64(0), previous, "a move from an empty pointer answers 0")
	assert.Equal(t, sql.NullInt64{Int64: other.Id, Valid: true}, defaultBrandIdOf(t, h))
}

// A database with no settings row has no default brand: a page drawn before the first start's seed
// commits is drawn without one.
func TestGetDefaultBrand_NoSettingsRowIsNil(t *testing.T) {
	h := migratedIsolatedDB(t)
	def, err := h.DB.GetDefaultBrand(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, def)
}

// A deletion racing a change of default never leaves the pointer on a deleted brand (#810 decision
// 1). Each order parks the first write inside its transaction, after it has taken the settings row
// and decided, and sends the other at the same brand: the second must wait for the first and then
// decide on what it committed. Without the lock the deletion reads the pointer as it stood before
// the move and deletes the brand the move is pointing at; the foreign key then refuses one of the
// two with an engine error rather than the refusal the API answers.
//
// On SQLite the pool has one connection, so the second write's transaction cannot open until the
// first commits: it waits in a different place, and what it then decides is the same.
func TestBrands_ADeletionRacingAChangeOfDefault(t *testing.T) {
	ctx := context.Background()
	h, seeded := brandsIsolatedDB(t)

	awaitBlocked := func(t *testing.T, done <-chan error, what string) {
		t.Helper()
		select {
		case err := <-done:
			t.Fatalf("%s completed while the other write held the settings row uncommitted (err %v)", what, err)
		case <-time.After(500 * time.Millisecond):
		}
	}
	awaitDone := func(t *testing.T, done <-chan error, what string) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			t.Fatalf("%s never returned after the other write committed", what)
			return nil
		}
	}

	t.Run("a move in flight, then a deletion of the brand it moves to", func(t *testing.T) {
		target := &record.Brand{Name: "Move target", Appearance: "light", Theme: "tangerine"}
		require.NoError(t, h.DB.CreateBrand(ctx, nil, target))

		move, err := h.DB.BeginTransaction(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = move.Rollback() })
		previous, err := h.DB.MakeBrandDefault(ctx, move, target.Id)
		require.NoError(t, err)
		require.Equal(t, seeded.Id, previous)

		done := make(chan error, 1)
		go func() { done <- deleteBrand(h, target.Id) }()
		awaitBlocked(t, done, "the deletion")

		require.NoError(t, h.DB.CommitTransaction(ctx, move))
		err = awaitDone(t, done, "the deletion")
		require.ErrorIs(t, err, data.ErrDefaultBrandNotDeletable, "the deletion decides on the committed move")

		assert.Equal(t, sql.NullInt64{Int64: target.Id, Valid: true}, defaultBrandIdOf(t, h))
		kept, err := h.DB.GetBrandById(ctx, nil, target.Id)
		require.NoError(t, err)
		assert.NotNil(t, kept, "the default brand is still there")
	})

	t.Run("a deletion in flight, then a move to the brand it deletes", func(t *testing.T) {
		before := defaultBrandIdOf(t, h)
		doomed := &record.Brand{Name: "Doomed", Appearance: "dark", Theme: "guava"}
		require.NoError(t, h.DB.CreateBrand(ctx, nil, doomed))

		deletion, err := h.DB.BeginTransaction(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = deletion.Rollback() })
		_, err = h.DB.DeleteBrand(ctx, deletion, doomed.Id)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() {
			_, moveErr := makeDefault(h, doomed.Id)
			done <- moveErr
		}()
		awaitBlocked(t, done, "the move")

		require.NoError(t, h.DB.CommitTransaction(ctx, deletion))
		err = awaitDone(t, done, "the move")
		require.ErrorIs(t, err, data.ErrBrandNotFound, "the move decides on the committed deletion")

		assert.Equal(t, before, defaultBrandIdOf(t, h), "the pointer stays where it was")
		gone, err := h.DB.GetBrandById(ctx, nil, doomed.Id)
		require.NoError(t, err)
		assert.Nil(t, gone, "the brand is deleted")
	})
}

// TestSeed_ANewInstallationHasADefaultBrand holds the first start to decision 1 on every engine:
// the seed writes a brand named Default, automatic, on Blueberry, and points the settings row at
// it in the same transaction.
func TestSeed_ANewInstallationHasADefaultBrand(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	outcome, err := bootstrap.Run(ctx, h.DB, dataCipher, seedConfig("admin@example.com"))
	require.NoError(t, err)
	require.Equal(t, bootstrap.Continue, outcome)

	brands, err := h.DB.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	require.Lenf(t, brands, 1, "the seed writes one brand on %s", dbType())
	assert.Equal(t, "Default", brands[0].Name)
	assert.Equal(t, record.BrandAppearance("auto"), brands[0].Appearance)
	assert.Equal(t, "blueberry", brands[0].Theme)
	assertBrandKit(t, &record.Brand{Corners: "rounded", Font: "system-ui", BackgroundFit: "cover"}, &brands[0],
		"the seeded brand is drawn as before the kit (#813)")

	assert.Equal(t, sql.NullInt64{Int64: brands[0].Id, Valid: true}, defaultBrandIdOf(t, h),
		"the settings row points at the seeded brand")
	def, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, def)
	assert.Equal(t, brands[0].Id, def.Id)
}
