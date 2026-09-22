// Package rsakey generates an RSA signing key and renders it in the four encodings the auth
// server stores it as: the private key as PEM, the public key as PEM, as DER and as a JWK, which
// is how /certs serves it.
//
// It is pure: it generates and encodes, and nothing else. Minting the key identifier, encrypting
// the private key at rest and building the stored row are signingkeys.NewKeyPair's, so this
// package imports neither the cipher nor the persistence models (#424).
//
// It belongs to the auth server because minting a signing key is the auth server's job (#360).
package rsakey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"

	"github.com/leodip/goiabada/core/errs"
)

// Material is one generated key pair in every encoding a signing key is stored in. Each field
// fills the models.KeyPair column of the same name.
type Material struct {
	// PrivateKeyPEM is the private key as PKCS#1 DER under the "RSA PRIVATE KEY" label, which is
	// the label PKCS#1 bytes carry. It is plaintext; the caller encrypts it before storing it.
	PrivateKeyPEM []byte
	// PublicKeyPEM is PublicKeyDER under the "PUBLIC KEY" label.
	PublicKeyPEM []byte
	// PublicKeyDER is the public key as a DER-encoded SubjectPublicKeyInfo.
	PublicKeyDER []byte
	// PublicKeyJWK is the public key as an RS256 signing JWK carrying the kid it was generated
	// with, indented JSON.
	PublicKeyJWK []byte
}

// Generate creates a validated RSA key of the given size and encodes it, the JWK carrying kid. It
// returns an error when crypto/rsa refuses the size, which it does below 1024 bits.
func Generate(bits int, kid string) (Material, error) {
	privateKey, err := generatePrivateKey(bits)
	if err != nil {
		return Material{}, errs.Wrap(err, "unable to generate a private key")
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return Material{}, errs.Wrap(err, "unable to marshal the public key")
	}

	publicKeyJWK, err := marshalJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return Material{}, err
	}

	return Material{
		PrivateKeyPEM: encodePrivateKeyPEM(privateKey),
		PublicKeyPEM:  encodePublicKeyPEM(publicKeyDER),
		PublicKeyDER:  publicKeyDER,
		PublicKeyJWK:  publicKeyJWK,
	}, nil
}

func generatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func encodePrivateKeyPEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// encodePublicKeyPEM labels SubjectPublicKeyInfo bytes "PUBLIC KEY", which RFC 7468 section 13
// requires of them. Keys generated before #424 carry "RSA PUBLIC KEY", the PKCS#1 label, over the
// same SubjectPublicKeyInfo bytes, and are not rewritten: golang-jwt reads either label, which
// signingkeys' tests hold, and a key is deleted two rotations after it stops being current. A
// strict reader that trusts the label, such as x509.ParsePKCS1PublicKey, refuses the old one.
func encodePublicKeyPEM(publicKeyDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})
}

func marshalJWK(publicKey *rsa.PublicKey, kid string) ([]byte, error) {
	jwk := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}{
		Alg: "RS256",
		Kid: kid,
		Kty: "RSA",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	publicKeyJWK, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return nil, errs.Wrap(err, "unable to marshal the public key to a JWK")
	}
	return publicKeyJWK, nil
}
