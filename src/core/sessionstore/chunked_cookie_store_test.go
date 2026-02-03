package sessionstore_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSessionName = "test-session"
	testAuthKey     = "12345678901234567890123456789012" // Exactly 32 bytes
	testEncryptKey  = "abcdefghijklmnopqrstuvwxyz123456" // Exactly 32 bytes
)

func TestChunkedStore_SmallSession(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))
	store.Options.Path = "/"
	store.Options.HttpOnly = true

	// Create request and response
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create session and add small data
	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["small_key"] = "small_value"
	session.Values["number"] = 42

	// Save session
	err = store.Save(req, w, session)
	require.NoError(t, err)

	// Check cookies were set
	cookies := w.Result().Cookies()
	assert.GreaterOrEqual(t, len(cookies), 1, "Should have at least master cookie")

	// Verify we can load the session back
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.False(t, session2.IsNew, "Session should be loaded, not new")
	assert.Equal(t, "small_value", session2.Values["small_key"])
	assert.Equal(t, 42, session2.Values["number"])
}

func TestChunkedStore_LargeSession(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create session with data > 4KB (will require multiple chunks)
	session, err := store.New(req, testSessionName)
	require.NoError(t, err)

	// Add 10KB of data
	largeData := strings.Repeat("X", 10000)
	session.Values["large_data"] = largeData
	session.Values["metadata"] = "This session is chunked"

	// Save session
	err = store.Save(req, w, session)
	require.NoError(t, err)

	// Check multiple cookies were created
	cookies := w.Result().Cookies()
	assert.Greater(t, len(cookies), 2, "Should have master + multiple chunk cookies")

	// Verify chunk cookies exist
	chunkCookieCount := 0
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, "-chunk-") {
			chunkCookieCount++
			assert.LessOrEqual(t, len(cookie.Value), 4096, "Each chunk should be under 4KB")
		}
	}
	assert.Greater(t, chunkCookieCount, 0, "Should have chunk cookies")

	// Verify we can load the large session back
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.False(t, session2.IsNew)
	assert.Equal(t, largeData, session2.Values["large_data"])
	assert.Equal(t, "This session is chunked", session2.Values["metadata"])
}

func TestChunkedStore_HugeSession(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create session with 100KB of data
	session, err := store.New(req, testSessionName)
	require.NoError(t, err)

	// Add multiple large values
	for i := 0; i < 5; i++ {
		key := "large_" + string(rune('a'+i))
		session.Values[key] = strings.Repeat("Y", 20000)
	}

	// Save session
	err = store.Save(req, w, session)
	require.NoError(t, err)

	// Verify large number of chunks
	cookies := w.Result().Cookies()
	chunkCount := 0
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, "-chunk-") {
			chunkCount++
		}
	}
	assert.Greater(t, chunkCount, 10, "Should have many chunks for 100KB session")

	// Verify reload works
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.False(t, session2.IsNew)

	// Verify all large values
	for i := 0; i < 5; i++ {
		key := "large_" + string(rune('a'+i))
		assert.Equal(t, strings.Repeat("Y", 20000), session2.Values[key])
	}
}

func TestChunkedStore_EmptySession(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create empty session
	session, err := store.New(req, testSessionName)
	require.NoError(t, err)

	// Save without adding any data
	err = store.Save(req, w, session)
	require.NoError(t, err)

	// Should still create cookies
	cookies := w.Result().Cookies()
	assert.GreaterOrEqual(t, len(cookies), 1)
}

func TestChunkedStore_SessionDeletion(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create and save a session
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["data"] = "to be deleted"
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()

	// Now delete the session
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	w2 := httptest.NewRecorder()
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)

	// Set MaxAge to -1 to delete
	session2.Options.MaxAge = -1
	err = store.Save(req2, w2, session2)
	require.NoError(t, err)

	// Check that delete cookies were set (MaxAge = -1)
	deleteCookies := w2.Result().Cookies()
	for _, cookie := range deleteCookies {
		assert.Equal(t, -1, cookie.MaxAge, "Delete cookies should have MaxAge = -1")
	}
}

func TestChunkedStore_MissingChunk(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create session with multiple chunks
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["large_data"] = strings.Repeat("Z", 10000)
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()

	// Remove one chunk cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		// Skip chunk-1 to simulate missing chunk
		if cookie.Name != testSessionName+"-chunk-1" {
			req2.AddCookie(cookie)
		}
	}

	// Attempt to load session should fail gracefully
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	// Should create new session since loading failed
	assert.True(t, session2.IsNew, "Should create new session when chunks are missing")
}

func TestChunkedStore_TamperedChunk(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create session with multiple chunks
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["data"] = strings.Repeat("A", 10000)
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()

	// Tamper with one chunk
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, "-chunk-1") {
			// Modify the cookie value
			cookie.Value = cookie.Value[:len(cookie.Value)-10] + "TAMPERED!!"
		}
		req2.AddCookie(cookie)
	}

	// Attempt to load should fail due to integrity check
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	// Should create new session since integrity check failed
	assert.True(t, session2.IsNew, "Should create new session when data is tampered")
}

func TestChunkedStore_MaxSizeExceeded(t *testing.T) {
	// Create store with very small max chunks limit
	store := sessionstore.NewChunkedCookieStoreWithConfig(3800, 2, []byte(testAuthKey), []byte(testEncryptKey))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)

	// Add data that requires more than 2 chunks
	session.Values["huge_data"] = strings.Repeat("X", 20000)

	// Save should fail with clear error
	err = store.Save(req, w, session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session too large")
	assert.Contains(t, err.Error(), "chunks")
}

func TestChunkedStore_UpdateSession(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create initial session
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["counter"] = 1
	session.Values["large_data"] = strings.Repeat("A", 5000) // Multiple chunks
	err = store.Save(req, w, session)
	require.NoError(t, err)

	initialCookies := w.Result().Cookies()

	// Update session with smaller data
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range initialCookies {
		req2.AddCookie(cookie)
	}

	w2 := httptest.NewRecorder()
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)

	session2.Values["counter"] = 2
	delete(session2.Values, "large_data") // Remove large data
	session2.Values["small_data"] = "small"

	err = store.Save(req2, w2, session2)
	require.NoError(t, err)

	// Load updated session
	req3 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range w2.Result().Cookies() {
		req3.AddCookie(cookie)
	}

	session3, err := store.New(req3, testSessionName)
	require.NoError(t, err)
	assert.False(t, session3.IsNew)
	assert.Equal(t, 2, session3.Values["counter"])
	assert.Equal(t, "small", session3.Values["small_data"])
	assert.Nil(t, session3.Values["large_data"])
}

func TestChunkedStore_ImplementsStoreInterface(t *testing.T) {
	var _ sessions.Store = (*sessionstore.ChunkedCookieStore)(nil)
}

func TestChunkedStore_MultipleSessionsIndependent(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create two different sessions
	session1, err := store.New(req, "session1")
	require.NoError(t, err)
	session1.Values["data"] = "session1_data"

	session2, err := store.New(req, "session2")
	require.NoError(t, err)
	session2.Values["data"] = "session2_data"

	// Save both
	err = store.Save(req, w, session1)
	require.NoError(t, err)
	err = store.Save(req, w, session2)
	require.NoError(t, err)

	// Load both back
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range w.Result().Cookies() {
		req2.AddCookie(cookie)
	}

	loadedSession1, err := store.New(req2, "session1")
	require.NoError(t, err)
	assert.Equal(t, "session1_data", loadedSession1.Values["data"])

	loadedSession2, err := store.New(req2, "session2")
	require.NoError(t, err)
	assert.Equal(t, "session2_data", loadedSession2.Values["data"])
}

func TestChunkedStore_MetadataValidation(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create session with data that requires multiple chunks
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["large_data"] = strings.Repeat("X", 10000)
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()

	// Find and verify master metadata cookie exists
	var masterCookie *http.Cookie
	chunkCount := 0
	for _, cookie := range cookies {
		if cookie.Name == testSessionName {
			masterCookie = cookie
		}
		if strings.Contains(cookie.Name, "-chunk-") {
			chunkCount++
		}
	}

	require.NotNil(t, masterCookie, "Master metadata cookie should exist")
	assert.Greater(t, chunkCount, 1, "Should have multiple chunk cookies")

	// Verify session loads correctly with metadata
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.False(t, session2.IsNew)
	assert.Equal(t, strings.Repeat("X", 10000), session2.Values["large_data"])
}

func TestChunkedStore_CorruptedMetadata(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create session
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["data"] = strings.Repeat("Y", 10000)
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()

	// Corrupt the master metadata cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		if cookie.Name == testSessionName {
			// Corrupt the metadata cookie value
			cookie.Value = cookie.Value[:len(cookie.Value)-20] + "CORRUPTED_METADATA!"
		}
		req2.AddCookie(cookie)
	}

	// Attempt to load should fail gracefully and create new session
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.True(t, session2.IsNew, "Should create new session when metadata is corrupted")
	assert.Nil(t, session2.Values["data"], "Should not have old data")
}

func TestChunkedStore_MismatchedChunkCount(t *testing.T) {
	store := sessionstore.NewChunkedCookieStore([]byte(testAuthKey), []byte(testEncryptKey))

	// Create session with multiple chunks
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, testSessionName)
	require.NoError(t, err)
	session.Values["data"] = strings.Repeat("Z", 15000)
	err = store.Save(req, w, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	originalChunkCount := 0
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, "-chunk-") {
			originalChunkCount++
		}
	}
	assert.Greater(t, originalChunkCount, 2, "Should have multiple chunks")

	// Remove the last chunk cookie (simulate chunk count mismatch)
	req2 := httptest.NewRequest("GET", "/", nil)
	lastChunkName := fmt.Sprintf("%s-chunk-%d", testSessionName, originalChunkCount-1)
	for _, cookie := range cookies {
		if cookie.Name != lastChunkName {
			req2.AddCookie(cookie)
		}
	}

	// Should fail to load and create new session
	session2, err := store.New(req2, testSessionName)
	require.NoError(t, err)
	assert.True(t, session2.IsNew, "Should create new session when chunk count mismatches")
}
