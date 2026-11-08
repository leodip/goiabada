package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// An authorization request's dpop_jkt, through the running server (RFC 9449 section 10, #42
// decision 14): validated where it enters, carried through every step of the sign-in to the code
// row, and checked at the token endpoint before the code is claimed, so a bound code is redeemed by
// its key alone and stays redeemable by it after another key, or none, was refused.

// boundCodeRefusal is the answer to a redemption of a bound code without a proof by its key.
var boundCodeRefusal = map[string]any{
	"error":             "invalid_grant",
	"error_description": "The authorization code is bound to a DPoP key, and the request carries no proof by that key.",
}

// ceremonyUser is who signs in when walkToCode meets a form.
type ceremonyUser struct {
	email, password, otpSecret string
}

// walkToCode follows the ceremony from resp, the answer to an authorization request, as a browser
// whose user fills each form it is shown: the password, a one-time code, consent to every scope, and
// acceptance of every legal document. It answers the code row the ceremony ended with, and the step
// pages it filled in on the way.
func walkToCode(t *testing.T, browser *http.Client, resp *http.Response, who ceremonyUser) (*record.Code, []string) {
	t.Helper()
	var pageURL string
	var filled []string
	for range 20 {
		switch resp.StatusCode {
		case http.StatusFound, http.StatusSeeOther:
			location := resp.Header.Get("Location")
			_ = resp.Body.Close()
			if !strings.HasPrefix(location, appConfig.AuthServer.BaseURL) {
				parsed, err := url.Parse(location)
				require.NoError(t, err)
				code := parsed.Query().Get("code")
				require.NotEmpty(t, code, "the ceremony ends at the client with a code: %s", location)
				return loadCodeFromDatabase(t, code), filled
			}
			pageURL = location
			resp = loadPage(t, browser, location)
		case http.StatusOK:
			page := resp
			parsed, err := url.Parse(pageURL)
			require.NoError(t, err)
			filled = append(filled, parsed.Path)
			switch parsed.Path {
			case "/auth/pwd":
				resp = authenticateWithPassword(t, browser, pageURL, page, who.email, who.password)
			case "/auth/otp":
				resp = authenticateWithOtp(t, browser, pageURL, page, otptest.Code(t, who.otpSecret, time.Now()))
			case "/auth/consent":
				resp = postConsent(t, browser, pageURL, page, consentIndices(t, page))
			case "/auth/legal-acceptance":
				_, documents := readStep(t, page)
				resp = postStep(t, browser, pageURL, page, versionsOf(documents), false)
			default:
				t.Fatalf("no form to fill on %s", pageURL)
			}
			_ = page.Body.Close()
		default:
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Fatalf("status %d at %q: %s", resp.StatusCode, pageURL, body)
		}
	}
	t.Fatal("the ceremony did not end in 20 steps")
	return nil, nil
}

// consentIndices is the index of every scope the consent page offers, so all are consented to.
func consentIndices(t *testing.T, page *http.Response) []int {
	t.Helper()
	raw, err := io.ReadAll(page.Body)
	require.NoError(t, err)
	page.Body = io.NopCloser(strings.NewReader(string(raw)))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(raw)))
	require.NoError(t, err)
	var indices []int
	doc.Find(`form input[type="checkbox"]`).Each(func(_ int, box *goquery.Selection) {
		name, _ := box.Attr("name")
		var i int
		if _, scanErr := fmt.Sscanf(name, "consent%d", &i); scanErr == nil {
			indices = append(indices, i)
		}
	})
	require.NotEmpty(t, indices, "the consent page offers a scope")
	return indices
}

// withDPoPJkt is the authorization request with dpop_jkt set to jkt, or without it when jkt is empty.
func withDPoPJkt(client *record.Client, redirectUri *record.RedirectURI, jkt string, extra map[string]string) string {
	overrides := map[string]string{"scope": "openid profile email"}
	for name, value := range extra {
		overrides[name] = value
	}
	if jkt != "" {
		overrides["dpop_jkt"] = jkt
	}
	return authorizeRequest(client, redirectUri, overrides)
}

// TestDPoPJkt_IsCarriedThroughEveryStepToTheCode signs in along each path the ceremony can take,
// with dpop_jkt, and finds the code row bound to that key: through the password form, from a POST
// parked for its GET, through consent, a one-time code, legal acceptance, the single sign-on
// shortcut and prompt=none. A request without dpop_jkt gets a code bound to no key.
func TestDPoPJkt_IsCarriedThroughEveryStepToTheCode(t *testing.T) {
	key := dpoptest.RFC7517Key(t)

	newUser := func(t *testing.T) ceremonyUser {
		user, password := newLegalAcceptanceUser(t)
		return ceremonyUser{email: user.Email, password: password}
	}

	for _, tc := range []struct {
		name string
		// run signs in with dpop_jkt set to jkt and answers the code and the forms filled.
		run    func(t *testing.T, jkt string) (*record.Code, []string)
		filled []string
	}{
		{
			name: "the password form",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				client, redirectUri := createTestClientAndRedirectURI(t)
				browser := createHttpClient(t)
				resp, err := browser.Get(withDPoPJkt(client, redirectUri, jkt, nil))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, newUser(t))
			},
			filled: []string{"/auth/pwd"},
		},
		{
			name: "a POST, parked for its GET",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				client, redirectUri := createTestClientAndRedirectURI(t)
				parsed, err := url.Parse(withDPoPJkt(client, redirectUri, jkt, nil))
				require.NoError(t, err)
				browser := createHttpClient(t)
				req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/auth/authorize/",
					strings.NewReader(parsed.Query().Encode()))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", "https://rp.example")
				resp, err := browser.Do(req)
				require.NoError(t, err)
				return walkToCode(t, browser, followParkedAuthorizePost(t, browser, resp), newUser(t))
			},
			filled: []string{"/auth/pwd"},
		},
		{
			name: "consent",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				client, redirectUri := createTestClientAndRedirectURI(t)
				client.ConsentRequired = true
				require.NoError(t, database.UpdateClient(context.Background(), nil, client))
				browser := createHttpClient(t)
				resp, err := browser.Get(withDPoPJkt(client, redirectUri, jkt, nil))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, newUser(t))
			},
			filled: []string{"/auth/pwd", "/auth/consent"},
		},
		{
			name: "a one-time code",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				client, redirectUri, user, password, otpSecret := createLevel2MandatoryUser(t, true)
				browser := createHttpClient(t)
				resp, err := browser.Get(withDPoPJkt(client, redirectUri, jkt, nil))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, ceremonyUser{email: user.Email, password: password, otpSecret: otpSecret})
			},
			filled: []string{"/auth/pwd", "/auth/otp"},
		},
		{
			name: "legal acceptance",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				f := newLegalAcceptanceFixture(t)
				f.mustAcceptFor(t, "terms", "Shop terms")
				extra := ""
				if jkt != "" {
					extra = "&dpop_jkt=" + url.QueryEscape(jkt)
				}
				browser := createHttpClient(t)
				resp, err := browser.Get(f.link(extra))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, ceremonyUser{email: f.user.Email, password: f.password})
			},
			filled: []string{"/auth/pwd", "/auth/legal-acceptance"},
		},
		{
			name: "the single sign-on shortcut",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				browser, client, redirectUri, _ := createSessionWithAcrLevel1(t)
				resp, err := browser.Get(withDPoPJkt(client, redirectUri, jkt, nil))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, ceremonyUser{})
			},
		},
		{
			name: "prompt=none",
			run: func(t *testing.T, jkt string) (*record.Code, []string) {
				browser, client, redirectUri, _ := createSessionWithAcrLevel1(t)
				resp, err := browser.Get(withDPoPJkt(client, redirectUri, jkt, map[string]string{"prompt": "none"}))
				require.NoError(t, err)
				return walkToCode(t, browser, resp, ceremonyUser{})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, filled := tc.run(t, key.Thumbprint)
			assert.Equal(t, tc.filled, filled, "the forms the sign-in went through")
			assert.Equal(t, sql.NullString{String: key.Thumbprint, Valid: true}, code.DPoPJkt, "the code is bound to dpop_jkt's key")
		})
		t.Run(tc.name+", without dpop_jkt", func(t *testing.T) {
			code, _ := tc.run(t, "")
			assert.Equal(t, sql.NullString{}, code.DPoPJkt, "the code is bound to no key")
		})
	}
}

// A dpop_jkt that is not the canonical form of a SHA-256 thumbprint, one sent twice, or one beside a
// response type that returns no code is refused invalid_request where it enters, before the
// sign-in, on the redirect to the client.
func TestDPoPJkt_AuthorizationRequestRefusals(t *testing.T) {
	const thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" // RFC 7638 section 3.1
	malformed := "The dpop_jkt parameter is incorrect. It must be the SHA-256 JWK thumbprint of the DPoP key (RFC 7638), " +
		"base64url-encoded without padding: 43 characters of A-Z, a-z, 0-9, '-' and '_'."
	client, redirectUri := createTestClientAndRedirectURI(t)

	for name, jkt := range map[string]string{
		"a spare bit set": thumbprint[:42] + "t",
		"padding":         thumbprint + "=",
		"42 characters":   thumbprint[:42],
		"44 characters":   thumbprint + "A",
		"a period":        thumbprint[:20] + "." + thumbprint[21:],
		"a tilde":         thumbprint[:20] + "~" + thumbprint[21:],
		"a CR":            thumbprint[:20] + "\r" + thumbprint[21:],
		"an LF":           thumbprint + "\n",
		"a space":         " " + thumbprint,
		"a tab":           thumbprint[:20] + "\t" + thumbprint[21:],
	} {
		t.Run(name, func(t *testing.T) {
			resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{"dpop_jkt": jkt}))
			errorCode, description, _ := getErrorFromUrl(t, resp)
			assert.Equal(t, "invalid_request", errorCode)
			assert.Equal(t, malformed, description)
		})
	}

	t.Run("sent twice", func(t *testing.T) {
		resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{"dpop_jkt": thumbprint})+
			"&dpop_jkt="+thumbprint)
		errorCode, description, _ := getErrorFromUrl(t, resp)
		assert.Equal(t, "invalid_request", errorCode)
		assert.Equal(t, "The 'dpop_jkt' parameter was included more than once.", description)
	})

	t.Run("a response type that returns no code", func(t *testing.T) {
		implicit, implicitRedirect := createTestClientAndRedirectURI(t)
		on := true
		implicit.ImplicitGrantEnabled = &on
		require.NoError(t, database.UpdateClient(context.Background(), nil, implicit))
		for _, responseType := range []string{"token", "id_token", "id_token token"} {
			t.Run(responseType, func(t *testing.T) {
				resp := answeredAtOnce(t, authorizeRequest(implicit, implicitRedirect, map[string]string{
					"response_type": responseType, "scope": "openid", "nonce": "the-nonce", "dpop_jkt": thumbprint,
				}))
				parsed, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				fragment, err := url.ParseQuery(parsed.Fragment)
				require.NoError(t, err)
				assert.Equal(t, "invalid_request", fragment.Get("error"))
				assert.Equal(t, "The dpop_jkt parameter binds the authorization code to a DPoP key, so it is accepted only with response_type=code.",
					fragment.Get("error_description"))
			})
		}
	})

	t.Run("a real thumbprint goes on to the sign-in", func(t *testing.T) {
		resp, err := createHttpClient(t).Get(authorizeRequest(client, redirectUri, map[string]string{"dpop_jkt": thumbprint}))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assertRedirect(t, resp, "/auth/level1")
	})
}

// A bound code is refused invalid_grant without a proof by its key, a proof by another key
// included, and stays unspent, so the key holder redeems it afterwards for tokens bound to its key.
func TestDPoPJkt_ABoundCodeIsRedeemedOnlyByItsKey(t *testing.T) {
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	_, code := createAuthCode(t, fake.LetterN(32), "openid profile", authCodeOptions{isPublic: true, dpopJkt: key.Thumbprint})
	require.Equal(t, sql.NullString{String: key.Thumbprint, Valid: true}, code.DPoPJkt)
	clientId := code.Client.ClientIdentifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientId},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}

	requireRefusedAndUnspent := func(t *testing.T, resp *http.Response, body map[string]any) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
		assert.Equal(t, boundCodeRefusal, body)
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		row, err := database.GetCodeById(context.Background(), nil, code.Id)
		require.NoError(t, err)
		assert.False(t, row.Used, "the refused redemption spent nothing")
		assert.False(t, row.Revoked)
	}

	t.Run("no proof", func(t *testing.T) {
		resp, body := postWithProof(t, form, clientId, "", "")
		requireRefusedAndUnspent(t, resp, body)
	})
	t.Run("a proof by another key", func(t *testing.T) {
		resp, body := postWithProof(t, form, clientId, "", other.Proof(t, "POST", dpopTokenURL(), time.Now(),
			nonceForRefresh(t, form, clientId, "", other)))
		requireRefusedAndUnspent(t, resp, body)
		require.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "the refusal of a DPoP request carries a fresh nonce")
	})
	t.Run("then a proof by its key", func(t *testing.T) {
		body := redeemWithDPoP(t, form, clientId, "", key)
		assertBoundTo(t, body, key)
		row, err := database.GetCodeById(context.Background(), nil, code.Id)
		require.NoError(t, err)
		assert.True(t, row.Used, "the code is spent by its key")
	})
	t.Run("and once spent, another key is still refused for the binding", func(t *testing.T) {
		resp, body := postWithProof(t, form, clientId, "", other.Proof(t, "POST", dpopTokenURL(), time.Now(),
			nonceForRefresh(t, form, clientId, "", other)))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
		assert.Equal(t, boundCodeRefusal, body)
	})
}

// Concurrent redemptions of one bound code, by its key, by another key and with no proof. Exactly
// one is answered tokens, and it is one by the code's key; every request without that key is refused
// for the binding, and every other by the key loses the code's claim. The code ends spent.
func TestDPoPJkt_ConcurrentRedemptionsOfABoundCodeHaveOneWinner(t *testing.T) {
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	_, code := createAuthCode(t, fake.LetterN(32), "openid profile", authCodeOptions{isPublic: true, dpopJkt: key.Thumbprint})
	clientId := code.Client.ClientIdentifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientId},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	nonce := nonceForRefresh(t, form, clientId, "", key)

	type attempt struct {
		byKey bool
		proof string
	}
	var attempts []attempt
	for range 4 {
		attempts = append(attempts, attempt{byKey: true, proof: key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonce)})
	}
	for range 2 {
		attempts = append(attempts, attempt{proof: other.Proof(t, "POST", dpopTokenURL(), time.Now(), nonce)})
		attempts = append(attempts, attempt{})
	}

	type outcome struct {
		status int
		body   map[string]any
		err    error
	}
	outcomes := make([]outcome, len(attempts))
	httpClient := createHttpClient(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, a := range attempts {
		wg.Add(1)
		go func(i int, a attempt) {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, dpopTokenURL(), strings.NewReader(form.Encode()))
			if err != nil {
				outcomes[i].err = err
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if a.proof != "" {
				req.Header.Set("DPoP", a.proof)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				outcomes[i].err = err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			outcomes[i].status = resp.StatusCode
			raw, _ := io.ReadAll(resp.Body)
			_ = json.Unmarshal(raw, &outcomes[i].body) // a non-JSON body leaves it nil; the status still classifies it
		}(i, a)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, a := range attempts {
		o := outcomes[i]
		require.NoErrorf(t, o.err, "request %d", i)
		if o.status == http.StatusOK {
			winners++
			assert.Truef(t, a.byKey, "request %d won without the code's key", i)
			assertBoundTo(t, o.body, key)
			continue
		}
		assert.Nilf(t, o.body["access_token"], "loser %d gets no access token", i)
		if !a.byKey {
			assert.Equalf(t, http.StatusBadRequest, o.status, "request %d", i)
			assert.Equalf(t, boundCodeRefusal, o.body, "request %d without the key is refused for the binding", i)
		}
	}
	assert.Equal(t, 1, winners, "exactly one redemption is answered tokens")

	row, err := database.GetCodeById(context.Background(), nil, code.Id)
	require.NoError(t, err)
	assert.True(t, row.Used, "the code is spent")
}
