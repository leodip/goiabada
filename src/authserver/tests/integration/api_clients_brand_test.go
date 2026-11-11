package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/brand gives a client a brand of its own, or with null puts it back
// on the default (#812 decision 2). The member is required; a brand that is not there is refused as
// a validation error. The route takes the client write scopes and the target ceiling, is audited as
// updated_client_brand, and every client the admin API answers carries brandId. A brand answers how
// many clients are drawn in it as clientCount (decision 3), and deleting a brand that is not the
// default moves its clients to the default (decision 1).

func clientBrandPath(clientId int64) string {
	return "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/brand"
}

// saveClientBrand sends one assignment and answers its status, its JSON body and its request id.
func saveClientBrand(t *testing.T, accessToken string, clientId int64, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, clientBrandPath(clientId), body)
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	return resp.StatusCode, decoded, requestId
}

// newOrdinaryClient is a confidential client holding no permission, deleted when the test ends.
func newOrdinaryClient(t *testing.T, prefix string) *record.Client {
	t.Helper()
	secret, err := dataCipher.Encrypt(fake.Password(60))
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         prefix + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    secret,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// newBrandInStore creates a brand through the data layer and deletes it when the test ends, which
// moves any client still given it back to the default.
func newBrandInStore(t *testing.T, prefix string) *record.Brand {
	t.Helper()
	ctx := context.Background()
	brand := &record.Brand{Name: brandName(prefix), Appearance: record.BrandAppearance("dark"), Theme: "plum"}
	require.NoError(t, database.CreateBrand(ctx, nil, brand))
	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := database.DeleteBrand(ctx, tx, brand.Id)
			if errors.Is(err, data.ErrBrandNotFound) {
				return nil
			}
			return err
		}))
	})
	return brand
}

// storedBrandId is the client's brand as the row holds it, 0 for none.
func storedBrandId(t *testing.T, clientId int64) int64 {
	t.Helper()
	client := storedClient(t, clientId)
	require.NotNil(t, client)
	if !client.BrandId.Valid {
		return 0
	}
	return client.BrandId.Int64
}

// readClientBrandId is brandId as GET /clients/{id} answers it: nil for null.
func readClientBrandId(t *testing.T, accessToken string, clientId int64) any {
	t.Helper()
	status, body, _ := brandCall(t, accessToken, http.MethodGet, "/api/v1/admin/clients/"+strconv.FormatInt(clientId, 10), nil)
	require.Equal(t, http.StatusOK, status, body)
	client := body["client"].(map[string]any)
	value, present := client["brandId"]
	require.True(t, present, "the client answer carries brandId, null included")
	return value
}

// brandClientCount is a brand's clientCount as GET /brands/{id} answers it.
func brandClientCount(t *testing.T, accessToken string, brandId int64) any {
	t.Helper()
	status, body, _ := brandCall(t, accessToken, http.MethodGet, brandPath(brandId, ""), nil)
	require.Equal(t, http.StatusOK, status, body)
	return body["brand"].(map[string]any)["clientCount"]
}

func TestAPIClientBrand_AssignsAndClearsTheBrand(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	client := newOrdinaryClient(t, "brand-assign-")
	brandId := createBrandOverAPI(t, accessToken, created, "Assigned "+fake.LetterN(10), "dark", "guava")
	brand, err := database.GetBrandById(context.Background(), nil, brandId)
	require.NoError(t, err)

	assert.Nil(t, readClientBrandId(t, accessToken, client.Id), "a new client starts on the default")

	status, body, requestId := saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": brandId})
	require.Equal(t, http.StatusOK, status, body)
	answered := body["client"].(map[string]any)
	assert.InDelta(t, float64(client.Id), answered["id"], 0)
	assert.InDelta(t, float64(brandId), answered["brandId"], 0, "the answer is the client as stored")
	assert.Equal(t, brandId, storedBrandId(t, client.Id))
	assert.InDelta(t, float64(brandId), readClientBrandId(t, accessToken, client.Id), 0)
	assert.Equal(t, []map[string]any{{
		"client_id":         float64(client.Id),
		"client_identifier": client.ClientIdentifier,
		"brand_id":          float64(brandId),
		"brand_name":        brand.Name,
		"logged_in_user":    caller.ClientIdentifier,
	}}, auditRows(t, accessToken, "updated_client_brand", requestId))

	// The listing carries it too.
	listing := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = listing.Body.Close() }()
	require.Equal(t, http.StatusOK, listing.StatusCode)
	var clients api.GetClientsResponse
	require.NoError(t, json.NewDecoder(listing.Body).Decode(&clients))
	found := false
	for _, listed := range clients.Clients {
		if listed.Id == client.Id {
			found = true
			require.NotNil(t, listed.BrandId)
			assert.Equal(t, brandId, *listed.BrandId)
		}
	}
	assert.True(t, found, "the client is in the listing")

	// The same brand again changes nothing and records nothing.
	status, body, requestId = saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": brandId})
	require.Equal(t, http.StatusOK, status, body)
	assert.InDelta(t, float64(brandId), body["client"].(map[string]any)["brandId"], 0)
	assert.Empty(t, auditRows(t, accessToken, "updated_client_brand", requestId))

	// null puts it back on the default; the event leaves the brand out.
	status, body, requestId = saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": nil})
	require.Equal(t, http.StatusOK, status, body)
	brandIdAnswer, present := body["client"].(map[string]any)["brandId"]
	assert.True(t, present, "brandId is answered as null, not left out")
	assert.Nil(t, brandIdAnswer)
	assert.Equal(t, int64(0), storedBrandId(t, client.Id))
	assert.Nil(t, readClientBrandId(t, accessToken, client.Id))
	assert.Equal(t, []map[string]any{{
		"client_id":         float64(client.Id),
		"client_identifier": client.ClientIdentifier,
		"logged_in_user":    caller.ClientIdentifier,
	}}, auditRows(t, accessToken, "updated_client_brand", requestId))

	// null again changes nothing and records nothing.
	status, _, requestId = saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": nil})
	require.Equal(t, http.StatusOK, status)
	assert.Empty(t, auditRows(t, accessToken, "updated_client_brand", requestId))
}

// A brand given explicitly stays given, also when it is the default brand.
func TestAPIClientBrand_TheDefaultBrandCanBeGivenExplicitly(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	defaultId, _ := keepDefaultBrand(t)
	client := newOrdinaryClient(t, "brand-explicit-")

	status, body, _ := saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": defaultId})
	require.Equal(t, http.StatusOK, status, body)
	assert.InDelta(t, float64(defaultId), body["client"].(map[string]any)["brandId"], 0)
	assert.Equal(t, defaultId, storedBrandId(t, client.Id))
}

func TestAPIClientBrand_Refusals(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	client := newOrdinaryClient(t, "brand-refusals-")
	kept := createBrandOverAPI(t, accessToken, created, brandName("Kept"), "auto", "plum")
	status, body, _ := saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": kept})
	require.Equal(t, http.StatusOK, status, body)

	// The member is required: a body without it is refused, not read as the default.
	status, body, requestId := saveClientBrand(t, accessToken, client.Id, map[string]any{})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.client_brand.brand_id_required", body["error_code"])
	assert.Equal(t, "brandId is required: send the id of a brand, or null for the default brand.", body["error_description"])
	assert.Equal(t, kept, storedBrandId(t, client.Id), "nothing changed")
	assert.Empty(t, auditRows(t, accessToken, "updated_client_brand", requestId))

	// A brand that is not there, and one deleted since it was read.
	gone := createBrandOverAPI(t, accessToken, created, brandName("Gone"), "auto", "plum")
	status, _, _ = brandCall(t, accessToken, http.MethodDelete, brandPath(gone, ""), nil)
	require.Equal(t, http.StatusOK, status)
	for _, missing := range []int64{gone, 999999999, 0, -4} {
		status, body, requestId = saveClientBrand(t, accessToken, client.Id, map[string]any{"brandId": missing})
		assert.Equalf(t, http.StatusBadRequest, status, "brand %d", missing)
		assert.Equalf(t, "handler.client_brand.brand_not_found", body["error_code"], "brand %d", missing)
		assert.Equal(t, "The brand does not exist.", body["error_description"])
		assert.Equal(t, kept, storedBrandId(t, client.Id), "nothing changed")
		assert.Empty(t, auditRows(t, accessToken, "updated_client_brand", requestId))
	}

	// A brandId that is not a number, and a body that is not an object.
	for _, malformed := range []any{map[string]any{"brandId": "7"}, map[string]any{"brandId": 1.5}, "not an object"} {
		status, body, _ = saveClientBrand(t, accessToken, client.Id, malformed)
		assert.Equalf(t, http.StatusBadRequest, status, "%v", malformed)
		assert.Equalf(t, "INVALID_REQUEST_BODY", body["error_code"], "%v", malformed)
	}
	assert.Equal(t, kept, storedBrandId(t, client.Id), "nothing changed")

	// An unknown client and a malformed id.
	status, body, _ = saveClientBrand(t, accessToken, 999999999, map[string]any{"brandId": kept})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	resp, _ := sendAdmin(t, accessToken, http.MethodPut, "/api/v1/admin/clients/abc/brand", map[string]any{"brandId": kept})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// The route takes the scopes of the client's other settings: manage-clients assigns a brand by its
// id, and still cannot list brands, which stay in the settings domain; admin-read and
// manage-settings cannot assign one.
func TestAPIClientBrand_Scopes(t *testing.T) {
	_, _ = keepDefaultBrand(t)
	client := newOrdinaryClient(t, "brand-scopes-")
	brand := newBrandInStore(t, "Scoped")

	clientsToken, clientsCaller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, clientsCaller.Id) })
	status, body, _ := saveClientBrand(t, clientsToken, client.Id, map[string]any{"brandId": brand.Id})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, brand.Id, storedBrandId(t, client.Id))
	status, _, _ = brandCall(t, clientsToken, http.MethodGet, brandsPath, nil)
	assert.Equal(t, http.StatusForbidden, status, "manage-clients does not list brands")

	for _, permission := range []string{builtin.AdminReadPermissionIdentifier, builtin.ManageSettingsPermissionIdentifier,
		builtin.ManageUsersPermissionIdentifier} {
		t.Run(permission, func(t *testing.T) {
			token, caller := createClientWithGranularScope(t, permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
			status, body, _ := saveClientBrand(t, token, client.Id, map[string]any{"brandId": nil})
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "INSUFFICIENT_SCOPE", body["error_code"])
			assert.Equal(t, brand.Id, storedBrandId(t, client.Id), "nothing changed")
		})
	}

	readToken, reader := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, reader.Id) })
	assert.InDelta(t, float64(brand.Id), readClientBrandId(t, readToken, client.Id), 0, "admin-read reads the brand")

	req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+clientBrandPath(client.Id), strings.NewReader(`{"brandId":null}`))
	require.NoError(t, err)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// The target ceiling for each kind of administrator client: the admin console's own, one allowed
// the administrative scopes, and one holding an administrative permission. A manage-clients token
// is refused 403 MANAGE_SCOPE_REQUIRED, the refusal is audited, and nothing is written; an
// authserver:manage token assigns the brand.
func TestAPIClientBrand_TheCeilingOnAdministratorClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	_, _ = keepDefaultBrand(t)
	brand := newBrandInStore(t, "Ceiling")
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	route := targetCeilingWrite{name: "PUT clients brand", method: http.MethodPut,
		route: "/api/v1/admin/clients/{id}/brand", kind: "client"}

	administrators := []struct {
		name   string
		client func(t *testing.T) *clientTargetFixture
	}{
		{"the admin console's own client", consoleClient},
		{"a client allowed the administrative scopes", func(t *testing.T) *clientTargetFixture {
			f := newTargetClient(t)
			require.NoError(t, database.SetClientAdministrativeScopesAllowed(context.Background(), nil, f.clientId, true))
			return f
		}},
		{"a client holding an administrative permission", func(t *testing.T) *clientTargetFixture {
			return newTargetClient(t, authServerPermissionId(t, builtin.ManageSettingsPermissionIdentifier))
		}},
	}
	for _, administrator := range administrators {
		t.Run(administrator.name, func(t *testing.T) {
			f := administrator.client(t)
			before := storedBrandId(t, f.clientId)
			t.Cleanup(func() {
				ctx := context.Background()
				var brandId sql.NullInt64
				if before != 0 {
					brandId = sql.NullInt64{Int64: before, Valid: true}
				}
				assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
					_, err := database.SetClientBrand(ctx, tx, f.clientId, brandId)
					return err
				}))
			})

			resp, requestId := sendAdmin(t, granularToken, http.MethodPut, clientBrandPath(f.clientId), map[string]any{"brandId": brand.Id})
			assertRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller, route, f.clientId)
			assert.Equal(t, before, storedBrandId(t, f.clientId), "the refused request changed nothing")
			assert.Empty(t, auditRows(t, manageToken, "updated_client_brand", requestId))

			status, body, requestId := saveClientBrand(t, manageToken, f.clientId, map[string]any{"brandId": brand.Id})
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, brand.Id, storedBrandId(t, f.clientId))
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}

	// The same manage-clients token assigns an ordinary client's brand.
	ordinary := newOrdinaryClient(t, "brand-ceiling-ordinary-")
	status, body, requestId := saveClientBrand(t, granularToken, ordinary.Id, map[string]any{"brandId": brand.Id})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, brand.Id, storedBrandId(t, ordinary.Id))
	assert.Empty(t, refusalRows(t, manageToken, requestId))
}

// clientCount counts the clients drawn in a brand: those given it, and for the default brand those
// with no brand of their own too, on every answer that carries a brand.
func TestAPIClientBrand_BrandsAnswerHowManyClientsTheyDraw(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	defaultId, created := keepDefaultBrand(t)
	first := newOrdinaryClient(t, "brand-count-a-")
	second := newOrdinaryClient(t, "brand-count-b-")
	explicit := newOrdinaryClient(t, "brand-count-c-")

	status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
		brandBody(map[string]any{"name": brandName("Counted"), "appearance": "light", "theme": "coconut"}))
	require.Equal(t, http.StatusCreated, status, body)
	counted := int64(body["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, counted)
	assert.InDelta(t, 0, body["brand"].(map[string]any)["clientCount"], 0, "a new brand draws no client")
	assert.InDelta(t, 0, brandClientCount(t, accessToken, counted), 0)

	for _, c := range []*record.Client{first, second} {
		status, body, _ = saveClientBrand(t, accessToken, c.Id, map[string]any{"brandId": counted})
		require.Equal(t, http.StatusOK, status, body)
	}
	status, body, _ = saveClientBrand(t, accessToken, explicit.Id, map[string]any{"brandId": defaultId})
	require.Equal(t, http.StatusOK, status, body)

	assert.InDelta(t, 2, brandClientCount(t, accessToken, counted), 0)

	// The list: the brand draws its two, and the default every client with no brand of its own
	// and the one given it, as the clients listing reads them.
	clientsResp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	var clients api.GetClientsResponse
	require.NoError(t, json.NewDecoder(clientsResp.Body).Decode(&clients))
	_ = clientsResp.Body.Close()
	onDefault := 0
	for _, c := range clients.Clients {
		if c.BrandId == nil || *c.BrandId == defaultId {
			onDefault++
		}
	}
	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandsPath, nil)
	require.Equal(t, http.StatusOK, status)
	listed := map[int64]any{}
	total := 0.0
	for _, b := range body["brands"].([]any) {
		brand := b.(map[string]any)
		listed[int64(brand["id"].(float64))] = brand["clientCount"]
		total += brand["clientCount"].(float64)
	}
	assert.InDelta(t, 2, listed[counted], 0)
	assert.InDelta(t, float64(onDefault), listed[defaultId], 0)
	assert.InDelta(t, float64(len(clients.Clients)), total, 0, "the counts of all brands add up to every client")

	// An update answers the count.
	status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(counted, ""),
		brandBody(map[string]any{"name": brandName("Recounted"), "appearance": "dark", "theme": "coconut"}))
	require.Equal(t, http.StatusOK, status, body)
	assert.InDelta(t, 2, body["brand"].(map[string]any)["clientCount"], 0)

	// Made the default, the brand draws its two and every client with no brand of its own; the
	// old default keeps only the client given it.
	status, body, _ = brandCall(t, accessToken, http.MethodPost, brandPath(counted, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, body)
	withoutBrand := onDefault - 1
	assert.InDelta(t, float64(2+withoutBrand), body["brand"].(map[string]any)["clientCount"], 0)
	assert.InDelta(t, 1, brandClientCount(t, accessToken, defaultId), 0)
}

// Deleting a brand that is not the default moves its clients to the default and records how many;
// the default brand is still refused, and its clients keep it.
func TestAPIClientBrand_DeletingABrandMovesItsClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	defaultId, created := keepDefaultBrand(t)
	first := newOrdinaryClient(t, "brand-move-a-")
	second := newOrdinaryClient(t, "brand-move-b-")
	name := brandName("Moving")
	moving := createBrandOverAPI(t, accessToken, created, name, "auto", "avocado")
	for _, c := range []*record.Client{first, second} {
		status, body, _ := saveClientBrand(t, accessToken, c.Id, map[string]any{"brandId": moving})
		require.Equal(t, http.StatusOK, status, body)
	}

	status, body, requestId := brandCall(t, accessToken, http.MethodDelete, brandPath(moving, ""), nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, int64(0), storedBrandId(t, first.Id), "moved to the default")
	assert.Equal(t, int64(0), storedBrandId(t, second.Id), "moved to the default")
	assert.Nil(t, readClientBrandId(t, accessToken, first.Id))
	assert.Equal(t, []map[string]any{{"brand_id": float64(moving), "brand_name": name, "client_count": float64(2),
		"logged_in_user": caller.ClientIdentifier}},
		auditRows(t, accessToken, "deleted_brand", requestId))
	assert.Empty(t, auditRows(t, accessToken, "updated_client_brand", requestId), "no event for each client")

	// The default brand, given to a client explicitly, is still refused.
	status, body, _ = saveClientBrand(t, accessToken, first.Id, map[string]any{"brandId": defaultId})
	require.Equal(t, http.StatusOK, status, body)
	status, body, requestId = brandCall(t, accessToken, http.MethodDelete, brandPath(defaultId, ""), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.default_delete_not_allowed", body["error_code"])
	assert.Equal(t, defaultId, storedBrandId(t, first.Id), "the client keeps the default brand given it")
	assert.Empty(t, auditRows(t, accessToken, "deleted_brand", requestId))
}
