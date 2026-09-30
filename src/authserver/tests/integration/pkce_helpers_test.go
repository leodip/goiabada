package integration

// testCodeVerifier is a PKCE code_verifier that satisfies RFC 7636 section 4.1, which the token
// endpoint has enforced since #244: 43 to 128 characters of ALPHA, DIGIT, "-", ".", "_" and "~". It
// is 51 characters. A test that needs several distinct verifiers appends a suffix of the same
// alphabet, and one that needs a well-formed verifier that does not match a stored challenge appends
// one to the verifier the challenge came from.
const testCodeVerifier = "code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
