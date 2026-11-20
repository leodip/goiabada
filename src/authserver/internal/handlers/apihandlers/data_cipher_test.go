package apihandlers

import "github.com/leodip/goiabada/authserver/internal/encryption"

// testDataCipher is the real cipher this package's tests seal and open with, under a fixed key.
// It is handed to what it tests, as main hands the process's cipher, rather than installed as a
// process-wide key; a case that needs a decrypt to fail builds a second cipher under another key
// instead of swapping this one (#434).
var testDataCipher = func() *encryption.DataCipher {
	dataCipher, err := encryption.NewDataCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	return dataCipher
}()

// The keys of a data key rotation, as the tests of a server write across a re-seal state them:
// the previous key is testDataCipher's, the one everything is sealed under before the rotation,
// and the current key is the new one (#492).
var (
	testPreviousDataKey = []byte("0123456789abcdef0123456789abcdef")
	testCurrentDataKey  = []byte("fedcba9876543210fedcba9876543210")
)

// rotatingDataCipher is the cipher of an auth server mid-rotation, as main builds it from both
// keys: it opens under the current key and then the previous one, and seals under the current.
var rotatingDataCipher = func() *encryption.DataCipher {
	dataCipher, err := encryption.NewDataCipherWithPrevious(testCurrentDataKey, testPreviousDataKey)
	if err != nil {
		panic(err)
	}
	return dataCipher
}()

// currentKeyOnlyCipher holds the current key alone, built apart from the cipher under test: a
// value is under the current key when this opens it, never when the code under test says so.
var currentKeyOnlyCipher = func() *encryption.DataCipher {
	dataCipher, err := encryption.NewDataCipher(testCurrentDataKey)
	if err != nil {
		panic(err)
	}
	return dataCipher
}()
