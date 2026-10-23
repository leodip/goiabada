// Package otp is the stateless TOTP primitive under the auth server's second factor: KeyGenerator
// mints a key as its otpauth:// URL, SecretFromKeyURL and RenderQRCodeImage derive the secret and
// the enrolment QR code from that one value, and MatchStep reports which time step produced a
// passcode, so the caller can record that step as consumed and refuse the passcode a second time
// (#111). The stored credential, its encryption and its replay record are otpcredential's.
//
// The profile is fixed: HOTP over HMAC-SHA-1 (RFC 4226), six digits, a 30-second step from the
// Unix epoch (RFC 6238), and a 20-byte secret from crypto/rand. It is computed here with the
// standard library, and the QR code drawn with boombuler/barcode, where pquerna/otp did both until
// #646; secrets, codes and stored key URLs read exactly as they did, and an ordinary App name
// mints a byte-identical URL. otptest, beside it, is a second implementation the tests take their
// codes from.
//
// An empty secret matches nothing, because the code an empty key derives depends only on the time
// and anyone can compute it. A passcode several steps produce is reported as the lowest step in its
// chain, so it is consumed once rather than once per colliding step as the window slides.
package otp
