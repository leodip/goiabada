package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWKSTokenParserRejectsNonRS256Token(t *testing.T) {
	tp := NewJWKSTokenParser("https://auth.example.com", nil)

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateTokenString(tokenString, nil, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid")
	assert.Nil(t, result)
}
