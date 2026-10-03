// Package otp is the stateless TOTP primitive under the auth server's second factor: KeyGenerator
// mints a key as its otpauth:// URL, SecretFromKeyURL and RenderQRCodeImage derive the secret and
// the enrolment QR code from that one value, and MatchStep reports which time step produced a
// passcode, so the caller can record that step as consumed and refuse the passcode a second time
// (#111). The stored credential, its encryption and its replay record are otpcredential's.
//
// An empty secret matches nothing, because the code an empty key derives depends only on the time
// and anyone can compute it. A passcode several steps produce is reported as the lowest step in its
// chain, so it is consumed once rather than once per colliding step as the window slides.
package otp
