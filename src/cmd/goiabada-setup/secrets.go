package main

import (
	"crypto/rand"
	"encoding/hex"
)

func generateHexKey(bytes int) string {
	key := make([]byte, bytes)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
