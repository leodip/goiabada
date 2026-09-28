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
