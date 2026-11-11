package datatests

import (
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

// A client's brand in storage (#812 decisions 1 and 3). clients.brand_id is the brand a client's
// pages are drawn in, or NULL to follow the default. It has its own writer, SetClientBrand, which
// takes the settings row's lock as the default pointer's writers do; a brand's deletion puts its
// clients back on the default under that same lock and answers how many it moved.
//
// Everything here runs on an isolated database seeded with settings row 1 and its Default brand
// (brandsIsolatedDB), because the default pointer is part of every answer and the counts are the
// installation's.

func brandId(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: true} }

// createIsolatedClient writes a client as every create path builds one: with no brand of its own.
func createIsolatedClient(t *testing.T, h *isolatedDB) *record.Client {
	t.Helper()
	client := &record.Client{ClientIdentifier: "brand_client_" + fake.LetterN(8), DefaultAcrLevel: record.AcrLevel1}
	require.NoError(t, h.DB.CreateClient(context.Background(), nil, client))
	return client
}

func createIsolatedBrand(t *testing.T, h *isolatedDB, name string) *record.Brand {
	t.Helper()
	brand := &record.Brand{Name: name, Appearance: "light", Theme: "avocado"}
	require.NoError(t, h.DB.CreateBrand(context.Background(), nil, brand))
	return brand
}

func assignBrand(h *isolatedDB, clientId int64, brand sql.NullInt64) (bool, error) {
	ctx := context.Background()
	var changed bool
	err := h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		changed, err = h.DB.SetClientBrand(ctx, tx, clientId, brand)
		return err
	})
	return changed, err
}

func setBrand(t *testing.T, h *isolatedDB, clientId int64, brand sql.NullInt64) bool {
	t.Helper()
	changed, err := assignBrand(h, clientId, brand)
	require.NoErrorf(t, err, "give client %d the brand %v on %s", clientId, brand, dbType())
	return changed
}

func deleteBrandMoving(h *isolatedDB, id int64) (int, error) {
	ctx := context.Background()
	var moved int
	err := h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		moved, err = h.DB.DeleteBrand(ctx, tx, id)
		return err
	})
	return moved, err
}

// clientBrandIdOf reads the column with raw SQL, a second read beside the data layer's.
func clientBrandIdOf(t *testing.T, h *isolatedDB, clientId int64) sql.NullInt64 {
	t.Helper()
	var id sql.NullInt64
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf("SELECT brand_id FROM clients WHERE id = %d", clientId)).Scan(&id),
		"read clients.brand_id on %s", dbType())
	return id
}

func clientUpdatedAtOf(t *testing.T, h *isolatedDB, clientId int64) time.Time {
	t.Helper()
	client, err := h.DB.GetClientById(context.Background(), nil, clientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.True(t, client.UpdatedAt.Valid)
	return client.UpdatedAt.Time
}

// TestSetClientBrand_TheColumnsOneWriter holds the writer to decision 1: a new client has no brand
// of its own; the writer assigns an existing brand and clears it, answering whether it changed
// anything, refuses a brand that does not exist, and touches no other client; every read of a
// client reads the column; and the whole-row client save writes it in neither direction.
func TestSetClientBrand_TheColumnsOneWriter(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	other := createIsolatedBrand(t, h, "Other")
	client := createIsolatedClient(t, h)
	bystander := createIsolatedClient(t, h)

	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, client.Id), "a new client has no brand of its own")

	// Assigned, read back by every read of a client.
	assert.True(t, setBrand(t, h, client.Id, brandId(other.Id)), "an assignment that changes the brand says so")
	assert.Equal(t, brandId(other.Id), clientBrandIdOf(t, h, client.Id))
	byId, err := h.DB.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	assert.Equal(t, brandId(other.Id), byId.BrandId, "GetClientById")
	byIdentifier, err := h.DB.GetClientByClientIdentifier(ctx, nil, client.ClientIdentifier)
	require.NoError(t, err)
	assert.Equal(t, brandId(other.Id), byIdentifier.BrandId, "GetClientByClientIdentifier")
	byIds, err := h.DB.GetClientsByIds(ctx, nil, []int64{client.Id, bystander.Id})
	require.NoError(t, err)
	require.Len(t, byIds, 2)
	all, err := h.DB.GetAllClients(ctx, nil)
	require.NoError(t, err)
	for _, list := range [][]record.Client{byIds, all} {
		for _, c := range list {
			switch c.Id {
			case client.Id:
				assert.Equal(t, brandId(other.Id), c.BrandId, "a list read reads the assigned brand")
			case bystander.Id:
				assert.Equal(t, sql.NullInt64{}, c.BrandId, "a list read reads no brand for the bystander")
			}
		}
	}
	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, bystander.Id), "the client not assigned is left as it was")

	// The same brand again changes nothing and writes nothing.
	stamped := clientUpdatedAtOf(t, h, client.Id)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, setBrand(t, h, client.Id, brandId(other.Id)), "an assignment of the brand the client has changes nothing")
	assert.True(t, stamped.Equal(clientUpdatedAtOf(t, h, client.Id)), "and writes nothing")

	// The default brand, assigned explicitly, is a brand of the client's own.
	assert.True(t, setBrand(t, h, client.Id, brandId(def.Id)))
	assert.Equal(t, brandId(def.Id), clientBrandIdOf(t, h, client.Id))

	// A brand that is not there is refused and writes nothing.
	_, err = assignBrand(h, client.Id, brandId(other.Id+1_000))
	require.ErrorIs(t, err, data.ErrBrandNotFound)
	assert.Equal(t, brandId(def.Id), clientBrandIdOf(t, h, client.Id), "a refused assignment leaves the brand")

	// Cleared, back on the default; clearing again changes nothing.
	assert.True(t, setBrand(t, h, client.Id, sql.NullInt64{}), "clearing the brand changes it")
	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, client.Id))
	assert.False(t, setBrand(t, h, client.Id, sql.NullInt64{}), "clearing a client with no brand changes nothing")

	// A client that is not there changes nothing.
	assert.False(t, setBrand(t, h, client.Id+1_000, brandId(other.Id)), "no client, nothing changed")

	// The whole-row save carries it in neither direction: a save made from a copy read earlier would
	// otherwise write back a brand changed since.
	setBrand(t, h, client.Id, brandId(other.Id))
	for _, carried := range []sql.NullInt64{{}, brandId(def.Id)} {
		read, readErr := h.DB.GetClientById(ctx, nil, client.Id)
		require.NoError(t, readErr)
		read.BrandId = carried
		read.Description = "rewritten_" + fake.LetterN(6)
		require.NoError(t, h.DB.UpdateClient(ctx, nil, read))
		assert.Equalf(t, brandId(other.Id), clientBrandIdOf(t, h, client.Id), "UpdateClient carrying %v must not write brand_id", carried)
		saved, readErr := h.DB.GetClientById(ctx, nil, client.Id)
		require.NoError(t, readErr)
		assert.Equal(t, read.Description, saved.Description, "and still writes the ordinary columns")
	}

	// The writer needs a transaction, as the lock it takes does.
	_, err = h.DB.SetClientBrand(ctx, nil, client.Id, brandId(def.Id))
	require.Error(t, err, "an assignment without a transaction")
	assert.Equal(t, brandId(other.Id), clientBrandIdOf(t, h, client.Id))
}

// TestDeleteBrand_MovesItsClientsToTheDefault holds the deletion to decisions 1 and 3: a brand that
// is not the default is deleted whatever its clients, which go back to the default, and the
// deletion answers how many it moved; the default is still refused and none of its clients is
// touched.
func TestDeleteBrand_MovesItsClientsToTheDefault(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	doomed := createIsolatedBrand(t, h, "Doomed")
	kept := createIsolatedBrand(t, h, "Kept")
	unused := createIsolatedBrand(t, h, "Unused")

	onDoomed1, onDoomed2 := createIsolatedClient(t, h), createIsolatedClient(t, h)
	onKept, onDefault, following := createIsolatedClient(t, h), createIsolatedClient(t, h), createIsolatedClient(t, h)
	setBrand(t, h, onDoomed1.Id, brandId(doomed.Id))
	setBrand(t, h, onDoomed2.Id, brandId(doomed.Id))
	setBrand(t, h, onKept.Id, brandId(kept.Id))
	setBrand(t, h, onDefault.Id, brandId(def.Id))

	moved, err := deleteBrandMoving(h, doomed.Id)
	require.NoError(t, err, "a brand clients use is deleted")
	assert.Equal(t, 2, moved, "the deletion answers the clients it moved")
	gone, err := h.DB.GetBrandById(ctx, nil, doomed.Id)
	require.NoError(t, err)
	assert.Nil(t, gone, "the brand is gone")
	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, onDoomed1.Id), "its clients are back on the default")
	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, onDoomed2.Id), "its clients are back on the default")
	assert.Equal(t, brandId(kept.Id), clientBrandIdOf(t, h, onKept.Id), "another brand's client stays")
	assert.Equal(t, brandId(def.Id), clientBrandIdOf(t, h, onDefault.Id), "the default's own client stays")
	assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, following.Id), "a client following the default stays")

	moved, err = deleteBrandMoving(h, unused.Id)
	require.NoError(t, err)
	assert.Equal(t, 0, moved, "a brand no client uses moves none")

	moved, err = deleteBrandMoving(h, def.Id)
	require.ErrorIs(t, err, data.ErrDefaultBrandNotDeletable, "the default brand is still refused")
	assert.Equal(t, 0, moved)
	assert.Equal(t, brandId(def.Id), clientBrandIdOf(t, h, onDefault.Id), "a refused deletion touches none of its clients")

	_, err = deleteBrandMoving(h, doomed.Id)
	require.ErrorIs(t, err, data.ErrBrandNotFound, "a second deletion finds nothing")

	_, err = h.DB.DeleteBrand(ctx, nil, kept.Id)
	require.Error(t, err, "a deletion without a transaction")
	assert.Equal(t, brandId(kept.Id), clientBrandIdOf(t, h, onKept.Id))
}

// TestCountClientsPerBrand holds the count to decision 3: a brand counts the clients drawn in it,
// those assigned to it and, for the default, those with no brand of their own, so the counts add up
// to the clients; a brand no client uses counts none, and the count follows the default.
func TestCountClientsPerBrand(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	other := createIsolatedBrand(t, h, "Other")
	unused := createIsolatedBrand(t, h, "Unused")

	counts, err := h.DB.CountClientsPerBrand(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, counts, "an installation with no client counts none")

	a, b, c := createIsolatedClient(t, h), createIsolatedClient(t, h), createIsolatedClient(t, h)
	createIsolatedClient(t, h)
	createIsolatedClient(t, h)
	setBrand(t, h, a.Id, brandId(other.Id))
	setBrand(t, h, b.Id, brandId(other.Id))
	setBrand(t, h, c.Id, brandId(def.Id))

	counts, err = h.DB.CountClientsPerBrand(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, map[int64]int{def.Id: 3, other.Id: 2}, counts,
		"the default counts its own client and the two following it; Unused counts none")
	assert.Zero(t, counts[unused.Id])

	// The clients following the default follow it to another brand; the one assigned stays.
	_, err = makeDefault(h, other.Id)
	require.NoError(t, err)
	counts, err = h.DB.CountClientsPerBrand(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, map[int64]int{def.Id: 1, other.Id: 4}, counts)

	// With no default, a client with no brand of its own is drawn in none.
	_, err = h.SQL.Exec("UPDATE settings SET default_brand_id = NULL WHERE id = 1")
	require.NoError(t, err)
	counts, err = h.DB.CountClientsPerBrand(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, map[int64]int{def.Id: 1, other.Id: 2}, counts)
}

// TestGetClientPageBrand holds the read of the brand a client's pages are drawn in to decision 1:
// the client's own brand when it has one, also when that brand is or stops being the default, and
// otherwise whichever brand is the default; none for a client that is not there or when nothing
// names a brand.
func TestGetClientPageBrand(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	other := &record.Brand{Name: "Other", Appearance: "dark", Theme: "plum"}
	require.NoError(t, h.DB.CreateBrand(ctx, nil, other))
	own := createIsolatedClient(t, h)
	onDefault := createIsolatedClient(t, h)
	following := createIsolatedClient(t, h)
	setBrand(t, h, own.Id, brandId(other.Id))
	setBrand(t, h, onDefault.Id, brandId(def.Id))

	drawnIn := func(identifier string) *record.Brand {
		t.Helper()
		brand, err := h.DB.GetClientPageBrand(ctx, nil, identifier)
		require.NoError(t, err)
		return brand
	}

	brand := drawnIn(own.ClientIdentifier)
	require.NotNil(t, brand, "a client with a brand of its own")
	assert.Equal(t, other.Id, brand.Id)
	assert.Equal(t, "Other", brand.Name)
	assert.Equal(t, record.BrandAppearance("dark"), brand.Appearance)
	assert.Equal(t, "plum", brand.Theme)
	require.NotNil(t, drawnIn(following.ClientIdentifier), "a client following the default")
	assert.Equal(t, def.Id, drawnIn(following.ClientIdentifier).Id)
	assert.Equal(t, "Default", drawnIn(following.ClientIdentifier).Name)
	assert.Equal(t, def.Id, drawnIn(onDefault.ClientIdentifier).Id)
	assert.Nil(t, drawnIn("no_such_client_"+fake.LetterN(6)), "a client that is not there names no brand")

	// The default moves: the client following it follows; an explicit assignment stays.
	_, err := makeDefault(h, other.Id)
	require.NoError(t, err)
	assert.Equal(t, other.Id, drawnIn(following.ClientIdentifier).Id, "a client following the default follows it")
	assert.Equal(t, def.Id, drawnIn(onDefault.ClientIdentifier).Id, "a brand assigned explicitly stays when it stops being the default")
	assert.Equal(t, other.Id, drawnIn(own.ClientIdentifier).Id)

	// With no default, a client with no brand of its own is drawn in none.
	_, err = h.SQL.Exec("UPDATE settings SET default_brand_id = NULL WHERE id = 1")
	require.NoError(t, err)
	assert.Nil(t, drawnIn(following.ClientIdentifier), "no brand of its own and no default")
	assert.Equal(t, other.Id, drawnIn(own.ClientIdentifier).Id, "its own brand needs no default")
}

// An assignment racing a brand's deletion is serialized by the settings row's lock (#812 decision
// 1), as TestBrands_ADeletionRacingAChangeOfDefault shows for the default pointer: an assignment
// that lands first is moved by the deletion and counted, and one that comes second finds the brand
// gone and is refused as a brand that does not exist, rather than by the foreign key.
func TestClientBrand_AnAssignmentRacingADeletion(t *testing.T) {
	ctx := context.Background()
	h, _ := brandsIsolatedDB(t)

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

	t.Run("an assignment in flight, then a deletion of the brand it assigns", func(t *testing.T) {
		target := createIsolatedBrand(t, h, "Assigned then deleted")
		client := createIsolatedClient(t, h)

		assignment, err := h.DB.BeginTransaction(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = assignment.Rollback() })
		changed, err := h.DB.SetClientBrand(ctx, assignment, client.Id, brandId(target.Id))
		require.NoError(t, err)
		require.True(t, changed)

		var moved int
		done := make(chan error, 1)
		go func() {
			var deleteErr error
			moved, deleteErr = deleteBrandMoving(h, target.Id)
			done <- deleteErr
		}()
		awaitBlocked(t, done, "the deletion")

		require.NoError(t, h.DB.CommitTransaction(ctx, assignment))
		require.NoError(t, awaitDone(t, done, "the deletion"), "the deletion moves the client the assignment committed")
		assert.Equal(t, 1, moved, "and counts it")
		assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, client.Id), "the client is back on the default")
		gone, err := h.DB.GetBrandById(ctx, nil, target.Id)
		require.NoError(t, err)
		assert.Nil(t, gone, "the brand is deleted")
	})

	t.Run("a deletion in flight, then an assignment of the brand it deletes", func(t *testing.T) {
		doomed := createIsolatedBrand(t, h, "Deleted then assigned")
		client := createIsolatedClient(t, h)

		deletion, err := h.DB.BeginTransaction(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = deletion.Rollback() })
		moved, err := h.DB.DeleteBrand(ctx, deletion, doomed.Id)
		require.NoError(t, err)
		require.Equal(t, 0, moved)

		done := make(chan error, 1)
		go func() {
			_, assignErr := assignBrand(h, client.Id, brandId(doomed.Id))
			done <- assignErr
		}()
		awaitBlocked(t, done, "the assignment")

		require.NoError(t, h.DB.CommitTransaction(ctx, deletion))
		err = awaitDone(t, done, "the assignment")
		require.ErrorIs(t, err, data.ErrBrandNotFound, "the assignment decides on the committed deletion")
		assert.Equal(t, sql.NullInt64{}, clientBrandIdOf(t, h, client.Id), "the client keeps following the default")
	})
}
