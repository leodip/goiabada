package data

// TLSMode is how the auth server protects its connection to PostgreSQL, MySQL or SQL Server:
// GOIABADA_DB_TLS_MODE, which takes libpq's sslmode names and means the same on all three engines
// (#502). SQLite has no connection to protect and reads none of it.
//
// The zero value is TLSPrefer, read through OrPrefer, so an engine configuration built directly,
// by the developer tools and the data tier's fixtures, connects as the auth server always has.
type TLSMode string

const (
	// TLSDisable never encrypts, even when the server offers TLS.
	TLSDisable TLSMode = "disable"
	// TLSPrefer is the default and what the auth server did before the setting existed: PostgreSQL
	// and MySQL encrypt when the server offers TLS and fall back to plain text when it offers none,
	// SQL Server encrypts the login, and the whole session when the server forces encryption. No
	// certificate is checked.
	TLSPrefer TLSMode = "prefer"
	// TLSRequire always encrypts the whole session and refuses a server offering no TLS, without
	// checking its certificate.
	TLSRequire TLSMode = "require"
	// TLSVerifyCA is TLSRequire, and the server's certificate chain is checked against the CA file
	// or, with none, the system roots. The host name is not checked.
	TLSVerifyCA TLSMode = "verify-ca"
	// TLSVerifyFull is TLSVerifyCA, and the certificate must name the host the auth server dials.
	TLSVerifyFull TLSMode = "verify-full"
)

// TLSModes is the five modes, from the one that protects least to the one that protects most.
func TLSModes() []TLSMode {
	return []TLSMode{TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull}
}

// Known reports whether m is one of the five modes, spelled exactly: no case folding and no
// driver's alias, such as MySQL's VERIFY_IDENTITY.
func (m TLSMode) Known() bool {
	switch m {
	case TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull:
		return true
	}
	return false
}

// ChecksCertificate reports whether m checks the server's certificate, which is what a CA file is
// read for: verify-ca and verify-full.
func (m TLSMode) ChecksCertificate() bool {
	return m == TLSVerifyCA || m == TLSVerifyFull
}

// OrPrefer is m, or TLSPrefer for the zero value.
func (m TLSMode) OrPrefer() TLSMode {
	if m == "" {
		return TLSPrefer
	}
	return m
}
