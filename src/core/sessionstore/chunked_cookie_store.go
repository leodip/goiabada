package sessionstore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

const (
	// DefaultChunkSize is the target size for each cookie chunk (bytes)
	// Set to 3800 to leave room for cookie metadata (~200 bytes)
	DefaultChunkSize = 3800

	// DefaultMaxChunks is the maximum number of chunks allowed
	// 50 chunks * 3800 bytes = ~190KB maximum session size
	DefaultMaxChunks = 50

	// MetadataVersion is the current protocol version
	MetadataVersion = 1
)

// ChunkedCookieStore implements sessions.Store interface with cookie chunking support.
// It splits large session data across multiple cookies to bypass the 4KB cookie limit.
type ChunkedCookieStore struct {
	// Codecs are used for secure cookie encoding/decoding (encryption + HMAC)
	Codecs []securecookie.Codec

	// Options contains default cookie options (path, domain, secure, etc.)
	Options *sessions.Options

	// chunkSize is the target size for each chunk in bytes
	chunkSize int

	// maxChunks is the maximum number of chunks allowed (prevents DoS)
	maxChunks int
}

// NewChunkedCookieStore creates a new chunked cookie store with default settings.
// keyPairs must contain pairs of authentication and encryption keys.
// For example: []byte(authKey), []byte(encryptionKey)
func NewChunkedCookieStore(keyPairs ...[]byte) *ChunkedCookieStore {
	return NewChunkedCookieStoreWithConfig(DefaultChunkSize, DefaultMaxChunks, keyPairs...)
}

// NewChunkedCookieStoreWithConfig creates a store with custom chunk size and limits.
// This allows fine-tuning for specific use cases.
func NewChunkedCookieStoreWithConfig(chunkSize, maxChunks int, keyPairs ...[]byte) *ChunkedCookieStore {
	codecs := securecookie.CodecsFromPairs(keyPairs...)

	// Disable MaxLength check in securecookie since we handle chunking ourselves
	// We encode the ENTIRE session first, then split it into chunks
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxLength(0) // 0 = no limit
		}
	}

	return &ChunkedCookieStore{
		Codecs: codecs,
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400, // Default 1 day
		},
		chunkSize: chunkSize,
		maxChunks: maxChunks,
	}
}

// Get retrieves an existing session or creates a new one.
// Implements sessions.Store interface.
func (s *ChunkedCookieStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New creates a new session and attempts to load existing session data from cookies.
// Implements sessions.Store interface.
func (s *ChunkedCookieStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true

	// Try to load existing session from cookies
	if cookie, err := r.Cookie(name); err == nil {
		if err := s.load(r, session, cookie.Value); err == nil {
			session.IsNew = false
		} else {
			// Log warning but don't fail - create new session instead
			slog.Warn("Failed to load existing session, creating new one",
				"error", err,
				"sessionName", name)
		}
	}

	return session, nil
}

// Save writes the session to chunked cookies.
// Implements sessions.Store interface.
func (s *ChunkedCookieStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete session if MaxAge < 0
	if session.Options.MaxAge < 0 {
		s.delete(w, session)
		return nil
	}

	// Encode session data using securecookie (encryption + HMAC)
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return errors.Wrap(err, "failed to encode session data")
	}

	// Split encoded data into chunks
	chunks := s.splitIntoChunks(encoded)

	// Validate chunk count doesn't exceed maximum
	if len(chunks) > s.maxChunks {
		return errors.Errorf("session too large: requires %d chunks (max %d). Estimated size: ~%d bytes. "+
			"Consider reducing session data or increasing maxChunks limit.",
			len(chunks), s.maxChunks, len(encoded))
	}

	// Calculate SHA256 hash of complete data for integrity verification
	hash := sha256.Sum256([]byte(encoded))
	dataHash := base64.StdEncoding.EncodeToString(hash[:])

	// Create metadata for master cookie
	metadata := ChunkMetadata{
		Version:    MetadataVersion,
		ChunkCount: len(chunks),
		DataHash:   dataHash,
		Timestamp:  time.Now().Unix(),
	}

	// Encode metadata
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	metadataEncoded, err := securecookie.EncodeMulti(session.Name()+"-meta", string(metadataJSON), s.Codecs...)
	if err != nil {
		return errors.Wrap(err, "failed to encode metadata")
	}

	// Write master metadata cookie
	http.SetCookie(w, s.createCookie(session.Name(), metadataEncoded, session.Options))

	// Write all data chunk cookies
	for i, chunk := range chunks {
		cookieName := fmt.Sprintf("%s-chunk-%d", session.Name(), i)
		http.SetCookie(w, s.createCookie(cookieName, chunk, session.Options))
	}

	// Clean up any old chunks beyond current count
	// This handles the case where session size decreased
	s.clearOldChunks(r, w, session.Name(), len(chunks))

	slog.Debug("Session saved",
		"sessionName", session.Name(),
		"chunkCount", len(chunks),
		"totalSize", len(encoded))

	return nil
}

// load reconstructs session data from chunked cookies.
func (s *ChunkedCookieStore) load(r *http.Request, session *sessions.Session, metadataEncoded string) error {
	// Decode metadata from master cookie
	var metadataJSON string
	if err := securecookie.DecodeMulti(session.Name()+"-meta", metadataEncoded, &metadataJSON, s.Codecs...); err != nil {
		return errors.Wrap(err, "failed to decode metadata cookie")
	}

	// Parse metadata JSON
	var metadata ChunkMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return errors.Wrap(err, "failed to unmarshal metadata")
	}

	// Validate metadata version
	if metadata.Version != MetadataVersion {
		return errors.Errorf("unsupported metadata version: %d (expected %d)", metadata.Version, MetadataVersion)
	}

	// Validate chunk count
	if metadata.ChunkCount <= 0 || metadata.ChunkCount > s.maxChunks {
		return errors.Errorf("invalid chunk count: %d (max %d)", metadata.ChunkCount, s.maxChunks)
	}

	// Read and reassemble all chunks
	var reassembled string
	for i := 0; i < metadata.ChunkCount; i++ {
		cookieName := fmt.Sprintf("%s-chunk-%d", session.Name(), i)
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return errors.Wrapf(err, "missing chunk cookie: %s (chunk %d of %d)", cookieName, i, metadata.ChunkCount)
		}
		reassembled += cookie.Value
	}

	// Verify data integrity using SHA256 hash
	hash := sha256.Sum256([]byte(reassembled))
	dataHash := base64.StdEncoding.EncodeToString(hash[:])
	if dataHash != metadata.DataHash {
		return errors.New("session data integrity check failed - chunks may be corrupted or tampered with")
	}

	// Decode session data using securecookie
	if err := securecookie.DecodeMulti(session.Name(), reassembled, &session.Values, s.Codecs...); err != nil {
		return errors.Wrap(err, "failed to decode session data")
	}

	slog.Debug("Session loaded",
		"sessionName", session.Name(),
		"chunkCount", metadata.ChunkCount)

	return nil
}

// splitIntoChunks splits encoded data into fixed-size chunks.
func (s *ChunkedCookieStore) splitIntoChunks(data string) []string {
	var chunks []string
	dataLen := len(data)

	for i := 0; i < dataLen; i += s.chunkSize {
		end := i + s.chunkSize
		if end > dataLen {
			end = dataLen
		}
		chunks = append(chunks, data[i:end])
	}

	return chunks
}

// createCookie creates an HTTP cookie with the provided name, value, and options.
func (s *ChunkedCookieStore) createCookie(name, value string, options *sessions.Options) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
}

// delete removes all session cookies (master and all chunks).
func (s *ChunkedCookieStore) delete(w http.ResponseWriter, session *sessions.Session) {
	options := *session.Options
	options.MaxAge = -1 // Delete cookie

	// Delete master metadata cookie
	http.SetCookie(w, s.createCookie(session.Name(), "", &options))

	// Delete all possible chunk cookies (up to maxChunks)
	// This is conservative but ensures cleanup even if metadata is corrupted
	for i := 0; i < s.maxChunks; i++ {
		cookieName := fmt.Sprintf("%s-chunk-%d", session.Name(), i)
		http.SetCookie(w, s.createCookie(cookieName, "", &options))
	}

	slog.Debug("Session deleted", "sessionName", session.Name())
}

// clearOldChunks removes chunk cookies beyond the current count.
// This handles the case where session size decreased.
func (s *ChunkedCookieStore) clearOldChunks(r *http.Request, w http.ResponseWriter, sessionName string, currentCount int) {
	options := *s.Options
	options.MaxAge = -1 // Delete cookie

	// Clear chunks from currentCount to maxChunks
	for i := currentCount; i < s.maxChunks; i++ {
		cookieName := fmt.Sprintf("%s-chunk-%d", sessionName, i)
		// Only delete if cookie exists (avoid unnecessary Set-Cookie headers)
		if _, err := r.Cookie(cookieName); err == nil {
			http.SetCookie(w, s.createCookie(cookieName, "", &options))
		}
	}
}
