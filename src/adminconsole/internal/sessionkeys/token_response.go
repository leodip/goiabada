package sessionkeys

import (
	"encoding/gob"

	"github.com/leodip/goiabada/core/oauth"
)

// storedShapeGobName is the name the token response under JWT is registered and written
// under: the one gob.Register derived from core/oauth's import path while the session stored
// oauth.TokenResponse itself. Every session in flight carries it, and a session whose value names
// one this binary has not registered fails to decode, which the store answers with a fresh session,
// signing the administrator out (#338).
const storedShapeGobName = "github.com/leodip/goiabada/core/oauth.TokenResponse"

// StoredTokenResponse is the token response as the console's session stores it under JWT, a shape
// of its own so that the stored format is not oauth.TokenResponse's Go declaration (#482 decision
// 6). gob writes a struct's field names into the session and matches them exactly, with no tags to
// declare them otherwise, so these seven names, and the registered name, are what a session written
// by an earlier binary holds and what one written by this binary must hold for an earlier binary to
// read it back. They are not respelled, whatever oauth.TokenResponse's fields are called.
type StoredTokenResponse struct {
	AccessToken      string
	IdToken          string //nolint:staticcheck // ST1003: gob stores this field by its name, which every session in flight holds (#482 decision 6)
	TokenType        string
	ExpiresIn        int64
	RefreshToken     string
	RefreshExpiresIn int64
	Scope            string
}

// RegisterStoredTokenResponse tells gob which type to decode a session's token response into, under
// the name sessions carry. main.go calls it at start-up, and a test that encodes or decodes a
// session holding one calls it too. Calling it again is a no-op.
func RegisterStoredTokenResponse() {
	gob.RegisterName(storedShapeGobName, StoredTokenResponse{})
}

// StoreTokenResponse is the value a session stores under JWT for tokenResponse.
func StoreTokenResponse(tokenResponse oauth.TokenResponse) StoredTokenResponse {
	return StoredTokenResponse{
		AccessToken:      tokenResponse.AccessToken,
		IdToken:          tokenResponse.IDToken,
		TokenType:        tokenResponse.TokenType,
		ExpiresIn:        tokenResponse.ExpiresIn,
		RefreshToken:     tokenResponse.RefreshToken,
		RefreshExpiresIn: tokenResponse.RefreshExpiresIn,
		Scope:            tokenResponse.Scope,
	}
}

// TokenResponse is the token response the session stored.
func (s StoredTokenResponse) TokenResponse() oauth.TokenResponse {
	return oauth.TokenResponse{
		AccessToken:      s.AccessToken,
		IDToken:          s.IdToken,
		TokenType:        s.TokenType,
		ExpiresIn:        s.ExpiresIn,
		RefreshToken:     s.RefreshToken,
		RefreshExpiresIn: s.RefreshExpiresIn,
		Scope:            s.Scope,
	}
}
