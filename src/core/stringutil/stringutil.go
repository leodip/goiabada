package stringutil

import (
	"crypto/rand"
	"log/slog"
	math_rand "math/rand"
	"strconv"
	"strings"
)

func GenerateSecurityRandomString(length int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return ""
	}

	for i, b := range bytes {
		bytes[i] = chars[b%byte(len(chars))]
	}

	return string(bytes)
}

func GenerateRandomLetterString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var sb strings.Builder
	sb.Grow(length)
	for i := 0; i < length; i++ {
		sb.WriteByte(letters[math_rand.Intn(len(letters))])
	}
	return sb.String()
}

func ConvertToString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		slog.Warn("ConvertToString: unsupported type", "type", val)
		return ""
	}
}

func GenerateRandomNumberString(length int) string {
	const chars = "0123456789"
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return ""
	}

	for i, b := range bytes {
		bytes[i] = chars[b%byte(len(chars))]
	}

	return string(bytes)
}
