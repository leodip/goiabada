package middleware

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
)

// TestRateLimiter_EveryTierDeclaresWhatItCountsBy holds each of the fifteen tiers the constructor
// builds to the kind #522 decision 11 gives it: seven by IP address, three by the account a form
// names, one by IP address and account, one by the signing-in user and three by the access token's
// user. The kinds are written here rather than read from the constructor, because the rate-limit
// table's Counted by column is held to the declaration, and a declaration changed by mistake would
// carry the table with it through a regenerated reading.
//
// Found by walking the struct, as the conventional-key test beside it finds them, so a sixteenth
// tier fails the count rather than going unchecked.
func TestRateLimiter_EveryTierDeclaresWhatItCountsBy(t *testing.T) {
	want := map[string]countedBy{
		"pwd_ip":                  countedByIP,
		"activate":                countedByIP,
		"register":                countedByIP,
		"reset_pwd":               countedByIP,
		"forgot_pwd_ip":           countedByIP,
		"dcr":                     countedByIP,
		"ropc_ip":                 countedByIP,
		"pwd_account":             countedByAccount,
		"register_email":          countedByAccount,
		"forgot_pwd_email":        countedByAccount,
		"pwd_account_net":         countedByIPAndAccount,
		"otp":                     countedBySigningInUser,
		"email_verification":      countedByTokenUser,
		"email_verification_send": countedByTokenUser,
		"account_password":        countedByTokenUser,
	}

	var tiers []foundTier
	collectTierKeyFields(reflect.ValueOf(newTestMiddleware(nil, true)), "middleware",
		&tiers, map[visitedValue]bool{})
	if len(tiers) != len(want) {
		t.Fatalf("walked %d tiers, expected the %d the constructor builds: %v", len(tiers), len(want), tiers)
	}
	for _, found := range tiers {
		kind, ok := want[found.name]
		if !ok {
			t.Errorf("tier %q at %s is not one of the fifteen this test knows", found.name, found.where)
			continue
		}
		if found.countedBy != kind {
			t.Errorf("tier %q at %s counts by %v, want %v", found.name, found.where, found.countedBy, kind)
		}
	}
}

// TestRateLimiter_EachKindDerivesItsBucket is the one derivation every Limit method keys through,
// over one request that carries all five things a tier can count by: the client address, an
// address typed into the form, the user of the ceremony the browser is in, and the subject of a
// validated access token. Each kind takes its own and nothing else, and names the identity a
// refusal's audit event records where the kind reads it; an account's is the route's, since only
// the route knows how its own lookup normalizes the address (#522 decision 10).
//
// The account is passed as typed, mixed case and surrounding space, so the account kinds are seen
// to apply ratelimit.AccountKey rather than take the text as it came.
func TestRateLimiter_EachKindDerivesItsBucket(t *testing.T) {
	const subject = "55555555-5555-5555-5555-555555555555"
	const account = "  Holder@Example.COM "

	request := func() *http.Request {
		req := limiterRequest(http.MethodPost, "/any?userId=42", nil)
		req.RemoteAddr = "203.0.113.7:5000"
		return req.WithContext(reqctx.WithValidatedToken(req.Context(),
			oauth.JwtToken{Claims: map[string]interface{}{"sub": subject}}))
	}

	cases := []struct {
		kind    countedBy
		key     string
		audited map[string]interface{}
	}{
		{countedByIP, "203.0.113.7", map[string]interface{}{"ip": "203.0.113.7"}},
		{countedByAccount, "holder@example.com", nil},
		{countedByIPAndAccount, "203.0.113.7|holder@example.com", nil},
		{countedBySigningInUser, "user_42", map[string]interface{}{"user_id": int64(42)}},
		{countedByTokenUser, subject, map[string]interface{}{"logged_in_user": subject}},
	}
	m := newTestMiddleware(stubCeremonyStore{}, true)
	for _, c := range cases {
		t.Run(c.kind.String(), func(t *testing.T) {
			key, audited, ok := m.bucket(request(), &tier{name: "probe", countedBy: c.kind}, account)
			if !ok || key != c.key || !reflect.DeepEqual(audited, c.audited) {
				t.Errorf("bucket = %q, %v, %v; want %q, %v, true", key, audited, ok, c.key, c.audited)
			}
		})
	}
}

// TestRateLimiter_AKindWithNoSubjectHasNoBucket is the two kinds that read a subject the request
// may not carry: no readable auth context for the signing-in user, no validated token or an empty
// subject for the token's user. Each answers no bucket, which the Limit method turns into a pass to
// the handler that answers such a request itself (#114).
func TestRateLimiter_AKindWithNoSubjectHasNoBucket(t *testing.T) {
	m := newTestMiddleware(stubCeremonyStore{err: ceremony.ErrNoAuthContext}, true)
	bare := limiterRequest(http.MethodPost, "/any", nil)
	blank := bare.WithContext(reqctx.WithValidatedToken(bare.Context(),
		oauth.JwtToken{Claims: map[string]interface{}{"sub": "  "}}))

	cases := []struct {
		name string
		kind countedBy
		r    *http.Request
	}{
		{"no auth context", countedBySigningInUser, bare},
		{"no validated token", countedByTokenUser, bare},
		{"an empty subject", countedByTokenUser, blank},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if key, audited, ok := m.bucket(c.r, &tier{name: "probe", countedBy: c.kind}, ""); ok {
				t.Errorf("bucket = %q, %v, true; want no bucket", key, audited)
			}
		})
	}
}

// TestRateLimiter_ATierDeclaringNoKindIsRefusedAtTheBucket is the zero value: a tier built without
// a kind is a programming fault, and deriving it a bucket would key it on something nobody
// declared, while answering no bucket would let every request through unlimited. It panics, which
// the recoverer answers 500, so the first request through such a tier says so.
func TestRateLimiter_ATierDeclaringNoKindIsRefusedAtTheBucket(t *testing.T) {
	m := newTestMiddleware(stubCeremonyStore{}, true)
	defer func() {
		if recover() == nil {
			t.Errorf("a tier declaring no kind was given a bucket")
		}
	}()
	m.bucket(limiterRequest(http.MethodPost, "/any", nil), &tier{name: "probe"}, "holder@example.com")
}
