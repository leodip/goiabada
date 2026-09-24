package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/imaging"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A request-body limit caps what a handler reads, and nothing more (#426 decision 14, answer A).
// A handler that stops reading after its value -- a JSON decode, a multipart parse at its closing
// boundary -- never reaches padding placed after that value, so a request whose value fits its row
// is served however much follows it. There is no Content-Length check and no read-ahead: either
// would refuse these requests, and decision 14 chose not to.
//
// Each case runs the real root chain and the real routes behind a real listener, so both framings
// are what net/http really receives, and counts what is read from the connection before the
// handler returns. The body is the value, then padding past the row's limit.

// paddedRequest is one decision 14 case.
type paddedRequest struct {
	method      string
	target      string
	contentType string
	// value is what the handler reads; padding follows it.
	value []byte
	// padding runs past the row, so the body as a whole is over its limit.
	padding []byte
	// limit is the row's, from bodyLimitPolicy.
	limit      int64
	wantStatus int
}

// readCount is what the wrapper outside the root chain saw of one request.
type readCount struct {
	read          int64
	contentLength int64
}

// newPaddingTestServer runs the real initMiddleware and initRoutes behind a listener. Outside the
// root chain, a wrapper counts what is read from the request body before the handler returns, and
// places the decoded bearer token where JwtAuthorizationHeaderToContext would: signature
// validation is not what these cases claim.
func newPaddingTestServer(t *testing.T, database *mocks_data.Database) (*httptest.Server, <-chan readCount) {
	t.Helper()

	s := newStaticBranchTestServer(database)
	s.templateFS = web.TemplateFS()
	s.initRoutes(s.initMiddleware())

	counts := make(chan readCount, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter := &countingReadCloser{ReadCloser: r.Body}
		r.Body = counter
		r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyBearerToken, accountAPIToken()))
		s.router.ServeHTTP(w, r)
		counts <- readCount{read: counter.read.Load(), contentLength: r.ContentLength}
	}))
	t.Cleanup(server.Close)
	return server, counts
}

type countingReadCloser struct {
	io.ReadCloser
	read atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// sendRaw writes the request straight onto a connection, with the framing spelled out rather than
// chosen by a client, and reads the response. The write runs beside the read: the server answers
// and closes once its handler returns, and a write the server stopped reading is expected to fail.
func sendRaw(t *testing.T, server *httptest.Server, request paddedRequest, chunked bool) *http.Response {
	t.Helper()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	body := append(append([]byte{}, request.value...), request.padding...)
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n",
		request.method, request.target, server.Listener.Addr().String(), request.contentType)
	if chunked {
		head.WriteString("Transfer-Encoding: chunked\r\n\r\n")
	} else {
		fmt.Fprintf(&head, "Content-Length: %d\r\n\r\n", len(body))
	}

	go func() {
		if _, writeErr := conn.Write([]byte(head.String())); writeErr != nil {
			return
		}
		if !chunked {
			_, _ = conn.Write(body)
			return
		}
		chunks := httputil.NewChunkedWriter(conn)
		for start := 0; start < len(body); start += 32 << 10 {
			if _, writeErr := chunks.Write(body[start:min(start+32<<10, len(body))]); writeErr != nil {
				return
			}
		}
		_ = chunks.Close()
		_, _ = conn.Write([]byte("\r\n"))
	}()

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func assertReadNoFurtherThanTheValue(t *testing.T, server *httptest.Server, counts <-chan readCount, request paddedRequest) {
	t.Helper()
	require.Greater(t, int64(len(request.value)+len(request.padding)), request.limit, "the body as a whole must be over its row")

	for _, chunked := range []bool{false, true} {
		t.Run(map[bool]string{false: "with Content-Length", true: "chunked"}[chunked], func(t *testing.T) {
			response := sendRaw(t, server, request, chunked)

			var count readCount
			select {
			case count = <-counts:
			case <-time.After(30 * time.Second):
				t.Fatal("the handler never returned")
			}

			if chunked {
				assert.Equal(t, int64(-1), count.contentLength, "the server saw no declared length")
			} else {
				assert.Equal(t, int64(len(request.value)+len(request.padding)), count.contentLength)
			}
			assert.Equal(t, request.wantStatus, response.StatusCode, "a value that fits its row is served, whatever follows it")
			assert.LessOrEqual(t, count.read, request.limit+1, "nothing past the row's limit reaches the handler")
			assert.Less(t, count.read, int64(len(request.value)+len(request.padding)), "the padding is never read")
		})
	}
}

// paddingTestSettings is what MiddlewareSettings reads. Registration is on so DCR reaches its
// decode; both audit sinks are off so the real AuditLogger writes no row.
func paddingTestSettings() *models.Settings {
	return &models.Settings{Id: 1, AppName: "Goiabada", DynamicClientRegistrationEnabled: true}
}

func TestBodyLimitPadding_DynamicClientRegistration(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(paddingTestSettings(), nil)
	database.On("CreateClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	database.On("CreateRedirectURI", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	server, counts := newPaddingTestServer(t, database)

	assertReadNoFurtherThanTheValue(t, server, counts, paddedRequest{
		method:      http.MethodPost,
		target:      "/connect/register",
		contentType: "application/json",
		value:       []byte(`{"client_name":"A Test Client","redirect_uris":["http://127.0.0.1:8765/callback"],"token_endpoint_auth_method":"none"}`),
		padding:     bytes.Repeat([]byte(" "), 1<<20),
		limit:       defaultBodyLimit,
		wantStatus:  http.StatusCreated,
	})
}

// The account phone PUT, one bearer JSON handler for the 45 that decode a body the same way.
func TestBodyLimitPadding_ABearerJSONHandler(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(paddingTestSettings(), nil)
	database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).
		Return(&models.User{Id: 1, Enabled: true, Subject: routesTestSubject}, nil)
	database.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	server, counts := newPaddingTestServer(t, database)

	assertReadNoFurtherThanTheValue(t, server, counts, paddedRequest{
		method:      http.MethodPut,
		target:      "/api/v1/account/phone",
		contentType: "application/json",
		// No phone at all, which clears it: the update the handler makes needs no country table.
		value:      []byte(`{"phoneCountryUniqueId":"","phoneNumber":""}`),
		padding:    bytes.Repeat([]byte(" "), 2<<20),
		limit:      apiBodyLimit,
		wantStatus: http.StatusOK,
	})
}

// The account picture upload: a multipart parse stops at the closing boundary, and what follows it
// is the epilogue, which RFC 2046 section 5.1.1 says to ignore.
func TestBodyLimitPadding_AnUpload(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(paddingTestSettings(), nil)
	database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).
		Return(&models.User{Id: 1, Enabled: true, Subject: routesTestSubject}, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, mock.Anything, int64(1)).Return(nil, nil)
	database.On("CreateUserProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	server, counts := newPaddingTestServer(t, database)

	picture := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := range 100 {
		for x := range 100 {
			picture.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var encoded bytes.Buffer
	require.NoError(t, png.Encode(&encoded, picture))

	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	part, err := writer.CreateFormFile("picture", "picture.png")
	require.NoError(t, err)
	_, err = part.Write(encoded.Bytes())
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	limit := bodyLimitPolicy(config.GetAuthServer().ProfilePictureMaxSizeBytes).Routes["POST /api/v1/account/profile-picture"]
	require.Equal(t, imaging.MaxFileSize(config.GetAuthServer().ProfilePictureMaxSizeBytes)+uploadMultipartAllowance, limit)

	assertReadNoFurtherThanTheValue(t, server, counts, paddedRequest{
		method:      http.MethodPost,
		target:      "/api/v1/account/profile-picture",
		contentType: writer.FormDataContentType(),
		value:       form.Bytes(),
		padding:     bytes.Repeat([]byte("x"), int(limit)),
		limit:       limit,
		wantStatus:  http.StatusOK,
	})
}
