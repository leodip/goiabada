package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math"
	"net/http"
	"net/url"

	"GoServerWebApp/config"

	"github.com/gorilla/sessions"
)

func LogoutHandler(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")

		// Get the ID token from the session
		idToken, ok := session.Values["id_token_raw"].(string)

		// Clear the local session
		session.Options.MaxAge = -1
		err := session.Save(r, w)
		if err != nil {
			http.Error(w, "Failed to clear session", http.StatusInternalServerError)
			return
		}

		if !ok || idToken == "" {
			// No valid ID token, redirect to index page
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Valid ID token present, proceed with OIDC-compliant logout
		encryptedIdToken, err := aesGcmEncryption(idToken, config.ClientSecret)
		if err != nil {
			http.Error(w, "Failed to encrypt ID token", http.StatusInternalServerError)
			return
		}

		logoutURL, err := url.Parse(config.OidcProvider + "/auth/logout")
		if err != nil {
			http.Error(w, "Failed to parse OIDC provider URL", http.StatusInternalServerError)
			return
		}

		query := logoutURL.Query()
		query.Set("id_token_hint", encryptedIdToken)
		query.Set("post_logout_redirect_uri", config.PostLogoutRedirectURL)
		query.Set("client_id", config.ClientId)
		query.Set("state", randomString(16))

		logoutURL.RawQuery = query.Encode()

		// Redirect to the OIDC provider's logout endpoint
		http.Redirect(w, r, logoutURL.String(), http.StatusFound)
	}
}

func aesGcmEncryption(idTokenUnencrypted string, clientSecret string) (string, error) {
	key := make([]byte, 32)

	// Use the first 32 bytes of the client secret as key
	keyBytes := []byte(clientSecret)
	copy(key, keyBytes[:int(math.Min(float64(len(keyBytes)), float64(len(key))))])

	// Random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText := aesGcm.Seal(nil, nonce, []byte(idTokenUnencrypted), nil)

	// Concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
	encrypted := make([]byte, len(nonce)+len(cipherText))
	copy(encrypted, nonce)
	copy(encrypted[len(nonce):], cipherText)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
