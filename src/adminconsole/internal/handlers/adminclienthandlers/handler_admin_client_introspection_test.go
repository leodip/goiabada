package adminclienthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// clientIntrospectionSaveApiClient records the request the Introspection tab's save hands the API,
// and the client it names, and answers it with err.
type clientIntrospectionSaveApiClient struct {
	err      error
	clientId int64
	sent     *api.UpdateClientIntrospectionResourcesRequest
}

func (s *clientIntrospectionSaveApiClient) UpdateClientIntrospectionResources(_ context.Context, _ string, clientId int64, request *api.UpdateClientIntrospectionResourcesRequest) error {
	s.clientId = clientId
	s.sent = request
	return s.err
}

// The rest of the ports clientIntrospectionSaveApiClient is passed to, which no save reaches.

func (*clientIntrospectionSaveApiClient) GetAllResources(context.Context, string) ([]api.ResourceResponse, error) {
	panic("unexpected call to GetAllResources")
}

func (*clientIntrospectionSaveApiClient) GetClientIntrospectionResources(context.Context, string, int64) (*api.ClientResponse, []api.ResourceResponse, error) {
	panic("unexpected call to GetClientIntrospectionResources")
}

func postIntrospection(clientId, body string) *http.Request {
	return handlertest.Request(http.MethodPost, "/admin/clients/"+clientId+"/introspection",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("clientId", clientId),
		handlertest.WithBody(bytes.NewBufferString(body)),
	)
}

// The page posts the list it wants beside the list as it loaded it, and the save hands both to the
// admin API unchanged, for the client the route names: the API compares the loaded list with the
// stored one and refuses a save from an outdated page (#428). [] is a page that loaded an empty list
// and must reach the wire as []; a body without the field must reach it as null, which the API
// refuses, rather than be defaulted to a list that would pass.
func TestHandleIntrospectionPost_SendsTheLoadedList(t *testing.T) {
	testCases := []struct {
		name         string
		body         string
		wantWanted   []int64
		wantExpected []int64
		wantWire     string
	}{
		{
			name:         "the loaded list passes through beside the wanted one",
			body:         `{"resourceIds":[4,6],"expectedResourceIds":[3,4]}`,
			wantWanted:   []int64{4, 6},
			wantExpected: []int64{3, 4},
			wantWire:     `{"resourceIds":[4,6],"expectedResourceIds":[3,4]}`,
		},
		{
			name:         "an empty loaded list stays an empty list",
			body:         `{"resourceIds":[6],"expectedResourceIds":[]}`,
			wantWanted:   []int64{6},
			wantExpected: []int64{},
			wantWire:     `{"resourceIds":[6],"expectedResourceIds":[]}`,
		},
		{
			name:         "every resource removed is an empty wanted list",
			body:         `{"resourceIds":[],"expectedResourceIds":[3]}`,
			wantWanted:   []int64{},
			wantExpected: []int64{3},
			wantWire:     `{"resourceIds":[],"expectedResourceIds":[3]}`,
		},
		{
			name:         "an absent loaded list stays absent",
			body:         `{"resourceIds":[6]}`,
			wantWanted:   []int64{6},
			wantExpected: nil,
			wantWire:     `{"resourceIds":[6],"expectedResourceIds":null}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// The API refuses, so the handler returns before the nil session is touched; the
			// request it sent is what is under test.
			stub := &clientIntrospectionSaveApiClient{err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
			HandleIntrospectionPost(render.New(nil, nil), nil, stub).ServeHTTP(httptest.NewRecorder(), postIntrospection("5", tc.body))

			require.NotNil(t, stub.sent)
			assert.Equal(t, int64(5), stub.clientId)
			assert.Equal(t, tc.wantWanted, stub.sent.ResourceIds)
			assert.Equal(t, tc.wantExpected, stub.sent.ExpectedResourceIds)
			wire, err := json.Marshal(stub.sent)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantWire, string(wire))
		})
	}
}

// The API's refusals the administrator can act on reach the tab's status region as the API's own
// code, sentence and status: a save from an outdated page, and a list for a client another
// administrator has made public since the page loaded.
func TestHandleIntrospectionPost_ARefusalReachesTheBrowser(t *testing.T) {
	testCases := []struct {
		name   string
		apiErr *apiclient.APIError
	}{
		{"a save from an outdated page", &apiclient.APIError{Code: "CONCURRENT_UPDATE",
			Message: "The list was changed by another save after it was loaded.", StatusCode: http.StatusConflict}},
		{"a client made public meanwhile", &apiclient.APIError{Code: "handler.client_introspection_resources.public_client",
			Message: "A public client can't introspect tokens, so it can't list introspection resources.", StatusCode: http.StatusBadRequest}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			HandleIntrospectionPost(render.New(nil, nil), nil, &clientIntrospectionSaveApiClient{err: tc.apiErr}).
				ServeHTTP(rec, postIntrospection("5", `{"resourceIds":[6],"expectedResourceIds":[3]}`))

			assert.Equal(t, tc.apiErr.StatusCode, rec.Code)
			var response map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			assert.Equal(t, tc.apiErr.Code, response["error"])
			assert.Equal(t, tc.apiErr.Message, response["error_description"])
		})
	}
}

// A save the API accepts answers the page's script with success and leaves the flash the reloaded
// tab says "saved" from.
func TestHandleIntrospectionPost_ASavedListAnswersSuccess(t *testing.T) {
	store := newTestSessionStore()
	stub := &clientIntrospectionSaveApiClient{}
	rec := httptest.NewRecorder()

	HandleIntrospectionPost(render.New(nil, nil), store, stub).
		ServeHTTP(rec, postIntrospection("5", `{"resourceIds":[6],"expectedResourceIds":[]}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"Success":true}`, rec.Body.String())
	require.NotNil(t, stub.sent)
}

// A body that is not JSON, and a route whose client id is not a number, are refused before the API
// is asked anything; the stub's unasked ports would panic.
func TestHandleIntrospectionPost_RefusesWhatItCannotRead(t *testing.T) {
	testCases := []struct {
		name       string
		request    *http.Request
		wantStatus int
		wantCode   string
	}{
		{"a body that is not JSON", postIntrospection("5", "{this is not json"), http.StatusBadRequest, "invalid_request_body"},
		{"a client id that is not a number", postIntrospection("five", `{"resourceIds":[],"expectedResourceIds":[]}`), http.StatusNotFound, "not_found"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &clientIntrospectionSaveApiClient{}
			rec := httptest.NewRecorder()
			HandleIntrospectionPost(render.New(nil, nil), nil, stub).ServeHTTP(rec, tc.request)

			assert.Nil(t, stub.sent, "nothing reaches the API")
			assert.Equal(t, tc.wantStatus, rec.Code)
			var response map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			assert.Equal(t, tc.wantCode, response["error"])
		})
	}
}
