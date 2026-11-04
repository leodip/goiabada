package sessionstore

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A page request refreshes its session when it first reads it, before its handler runs, and the
// refreshed cookie waits for the response's headers: by then another request of the same browser
// may have rotated the session or ended it and answered first, and the request itself may have
// written the session's cookie, either of which the refreshed cookie must not undo (#743).

// staleSignedInSession is the auth server's kind of store under rule, holding one signed-in
// session whose row was last accessed a minute ago, and the cookie naming it.
func staleSignedInSession(t *testing.T, rule KeepSignedIn) (*ConditionalStore, *fakeBackend, *http.Cookie, string) {
	t.Helper()
	store, backend := keepTestStore(t, rule)
	cookie := saveNew(t, store.ServerSideStore, signedInValues())
	id := decodeCookieId(t, store.ServerSideStore, cookie)
	backend.rows[id].LastAccessed = keepTestNow.Add(-time.Minute)
	return store, backend, cookie, id
}

// sessionCookies are the Set-Cookie lines of the store's session cookie on a recorded response, as
// the browser received them: the headers when the status went out.
func sessionCookies(store *ConditionalStore, w *httptest.ResponseRecorder) []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == store.CookieName(storeTestName) {
			cookies = append(cookies, cookie)
		}
	}
	return cookies
}

// serveRefreshing answers req through Refreshing, with a handler that reads the session, which is
// the refresh, then hands the request to handle, which answers it. A failure of either is asserted
// once the handler returns, as testifylint asks of a handler.
func serveRefreshing(t *testing.T, store *ConditionalStore, req *http.Request, handle func(w http.ResponseWriter, r *http.Request) error) *httptest.ResponseRecorder {
	t.Helper()
	var handlerErr error
	w := httptest.NewRecorder()
	Refreshing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, handlerErr = store.Get(r, storeTestName); handlerErr == nil {
			handlerErr = handle(w, r)
		}
	})).ServeHTTP(w, req)
	require.NoError(t, handlerErr)
	return w
}

// While the page request works, another request of the same browser rotates the session, as a
// sign-in in another tab does when its password is accepted, or ends it, as a sign-out there does,
// and answers first. The page request's answer arrives last, so a refreshed cookie on it would
// name a row that is gone and sign the browser out. It sends none, whether the rule keeps the
// session or not.
func TestRefreshing_SendsNoCookieForASessionAnotherRequestRotatedOrEndedMeanwhile(t *testing.T) {
	for ruleName, rule := range map[string]KeepSignedIn{"kept": keepEverySignedInSession, "not kept": keepNoSignedInSession} {
		for otherName, other := range map[string]func(store *ConditionalStore, cookie *http.Cookie) error{
			"rotated": func(store *ConditionalStore, cookie *http.Cookie) error {
				r := requestWith(cookie)
				session, err := store.Get(r, storeTestName)
				if err != nil {
					return err
				}
				return store.ChangeAndRegenerate(httptest.NewRecorder(), r, session, func(map[string]any) error { return nil })
			},
			"ended": func(store *ConditionalStore, cookie *http.Cookie) error {
				r := requestWith(cookie)
				session, err := store.Get(r, storeTestName)
				if err != nil {
					return err
				}
				session.Options.MaxAge = -1
				return store.Save(r, httptest.NewRecorder(), session)
			},
		} {
			t.Run(ruleName+", "+otherName, func(t *testing.T) {
				store, backend, cookie, id := staleSignedInSession(t, rule)
				touchesAtRefresh := 0

				w := serveRefreshing(t, store, requestWith(cookie), func(w http.ResponseWriter, _ *http.Request) error {
					touchesAtRefresh = backend.touches
					if err := other(store, cookie); err != nil {
						return err
					}
					w.WriteHeader(http.StatusOK)
					return nil
				})

				require.Equal(t, 1, touchesAtRefresh, "the read refreshed the session")
				require.NotContains(t, backend.rows, id, "the other request removed the row")
				assert.Empty(t, sessionCookies(store, w))
			})
		}
	}
}

// While the page request works, another request of the same browser writes the session anew under
// the same identifier, as a password entry in another tab does when it records an unticked Keep me
// signed in box, and answers first with a cookie that ends with the browser. The page request read
// the ticked answer, so its refreshed cookie would outlive the browser, and arriving last it would
// keep the session past a restart the user just declined. It sends none: the row no longer holds
// what the refresh read.
func TestRefreshing_SendsNoCookieBuiltFromContentsAnotherRequestRewroteMeanwhile(t *testing.T) {
	store, backend := keepTestStore(t, func(_ context.Context, values map[string]any) (bool, error) {
		ticked, _ := values["KeepSignedIn"].(bool)
		return ticked, nil
	})
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"SessionIdentifier": "a-user-session", "KeepSignedIn": true})
	id := decodeCookieId(t, store.ServerSideStore, cookie)
	backend.rows[id].LastAccessed = keepTestNow.Add(-time.Minute)
	var otherCookies []*http.Cookie

	w := serveRefreshing(t, store, requestWith(cookie), func(w http.ResponseWriter, _ *http.Request) error {
		r := requestWith(cookie)
		session, err := store.Get(r, storeTestName)
		if err != nil {
			return err
		}
		other := httptest.NewRecorder()
		if err := store.ChangeAndSave(r, other, session, func(values map[string]any) error {
			values["KeepSignedIn"] = false
			return nil
		}); err != nil {
			return err
		}
		otherCookies = sessionCookies(store, other)
		w.WriteHeader(http.StatusOK)
		return nil
	})

	require.Len(t, otherCookies, 1, "the other request names the session itself")
	assertEndsWithTheBrowser(t, otherCookies[0])
	require.Contains(t, backend.rows, id, "under the same identifier")
	assert.Empty(t, sessionCookies(store, w))
}

// A request that writes the session's cookie itself, as a save does when a password entry records
// a new Keep me signed in answer, answers with that cookie alone: the refreshed one, held until the
// headers go out, would otherwise follow it and the browser would keep the older answer's.
func TestRefreshing_ACookieTheRequestWritesItselfStandsAlone(t *testing.T) {
	store, _, cookie, _ := staleSignedInSession(t, func(_ context.Context, values map[string]any) (bool, error) {
		ticked, _ := values["KeepSignedIn"].(bool)
		return ticked, nil
	})

	w := serveRefreshing(t, store, requestWith(cookie), func(w http.ResponseWriter, r *http.Request) error {
		session, err := store.Get(r, storeTestName)
		if err != nil {
			return err
		}
		session.Values["KeepSignedIn"] = true
		if err := store.Save(r, w, session); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})

	cookies := sessionCookies(store, w)
	require.Len(t, cookies, 1, "one cookie, the save's")
	assert.Equal(t, int(keepTestRowLifetime.Seconds()), cookies[0].MaxAge, "under the answer the save recorded")
}

// The refreshed cookie goes out with the headers however the response first sends them: a status,
// the body's first bytes, a flush, or nothing at all, where net/http answers once the handler
// returns.
func TestRefreshing_TheCookieGoesOutWithTheHeadersHoweverTheyAreSent(t *testing.T) {
	for name, answer := range map[string]func(w http.ResponseWriter, _ *http.Request) error{
		"a status": func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusSeeOther)
			return nil
		},
		"a body": func(w http.ResponseWriter, _ *http.Request) error {
			_, err := w.Write([]byte("a page"))
			return err
		},
		"a flush": func(w http.ResponseWriter, _ *http.Request) error { return http.NewResponseController(w).Flush() },
		"nothing": func(http.ResponseWriter, *http.Request) error { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			store, _, cookie, id := staleSignedInSession(t, keepEverySignedInSession)

			w := serveRefreshing(t, store, requestWith(cookie), answer)

			cookies := sessionCookies(store, w)
			require.Len(t, cookies, 1)
			assert.Equal(t, id, decodeCookieId(t, store.ServerSideStore, cookies[0]))
			assert.Equal(t, int(keepTestRowLifetime.Seconds()), cookies[0].MaxAge)
		})
	}
}

// A handler that panics after the refresh leaves the answer to the recoverer above, as the auth
// server's root httpmw.Recoverer, which writes its 500 on the writer it was given, beneath
// Refreshing's. The refreshed cookie still goes out on that 500: the row was touched, and under a
// stricter setting the cookie is what replaces one that outlives the browser.
func TestRefreshing_TheCookieGoesOutOnTheAnswerToAPanic(t *testing.T) {
	store, _, cookie, id := staleSignedInSession(t, keepNoSignedInSession)
	var readErr error
	recoverer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recover() != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}

	w := httptest.NewRecorder()
	recoverer(Refreshing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, readErr = store.Get(r, storeTestName); readErr == nil {
			panic("a handler fault")
		}
	}))).ServeHTTP(w, requestWith(cookie))

	require.NoError(t, readErr)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	cookies := sessionCookies(store, w)
	require.Len(t, cookies, 1)
	assert.Equal(t, id, decodeCookieId(t, store.ServerSideStore, cookies[0]))
	assertEndsWithTheBrowser(t, cookies[0])
}

// An informational answer, such as 103 Early Hints, is not the answer the cookie waits for: net/http
// sends the headers with it and keeps them for the final one. The cookie stays held through it, so
// a rotation by another request after the 103 still keeps it off the final answer, and with nothing
// in between it goes out on the final answer. Through a real server, since a recorder takes the
// first status it is given for the final one.
func TestRefreshing_AnInformationalAnswerLeavesTheCookieHeld(t *testing.T) {
	for name, test := range map[string]struct {
		rotate     bool
		wantCookie bool
	}{
		"another request rotates the session after the 103": {rotate: true},
		"nothing happens after the 103":                     {wantCookie: true},
	} {
		t.Run(name, func(t *testing.T) {
			store, _, cookie, id := staleSignedInSession(t, keepEverySignedInSession)
			handlerErr := make(chan error, 1)
			server := httptest.NewServer(Refreshing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := store.Get(r, storeTestName); err != nil {
					handlerErr <- err
					return
				}
				w.Header().Set("Link", "</styles.css>; rel=preload; as=style")
				w.WriteHeader(http.StatusEarlyHints)
				if test.rotate {
					other := requestWith(cookie)
					session, err := store.Get(other, storeTestName)
					if err == nil {
						err = store.ChangeAndRegenerate(httptest.NewRecorder(), other, session, func(map[string]any) error { return nil })
					}
					if err != nil {
						handlerErr <- err
						return
					}
				}
				w.WriteHeader(http.StatusOK)
				handlerErr <- nil
			})))
			defer server.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			req.AddCookie(cookie)
			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.NoError(t, <-handlerErr)

			require.Equal(t, http.StatusOK, resp.StatusCode, "the final answer")
			var cookies []*http.Cookie
			for _, set := range resp.Cookies() {
				if set.Name == store.CookieName(storeTestName) {
					cookies = append(cookies, set)
				}
			}
			if test.wantCookie {
				require.Len(t, cookies, 1)
				assert.Equal(t, id, decodeCookieId(t, store.ServerSideStore, cookies[0]))
			} else {
				assert.Empty(t, cookies, "no cookie names the rotated-away row")
			}
		})
	}
}

// When the row cannot be read before the headers go out, no cookie is sent: the browser keeps the
// one it has, where a cookie naming a removed row would sign it out. The failure is logged, unless
// the browser abandoned the request, which ends its reads too and is no fault.
func TestRefreshing_ARowThatCannotBeReadSendsNoCookie(t *testing.T) {
	for name, test := range map[string]struct {
		abandoned bool
		logged    bool
	}{
		"a read that fails":   {logged: true},
		"an abandoned answer": {abandoned: true},
	} {
		t.Run(name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			store, backend, cookie, _ := staleSignedInSession(t, keepEverySignedInSession)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			w := serveRefreshing(t, store, requestWith(cookie).WithContext(ctx), func(w http.ResponseWriter, _ *http.Request) error {
				backend.loadErr = errors.New("database unavailable")
				if test.abandoned {
					cancel()
				}
				w.WriteHeader(http.StatusOK)
				return nil
			})

			assert.Empty(t, sessionCookies(store, w))
			var warnings []logtest.CapturedRecord
			for _, record := range capture.Records() {
				if record.Level == slog.LevelWarn {
					warnings = append(warnings, record)
				}
			}
			if test.logged {
				require.Len(t, warnings, 1)
				assert.Equal(t, "unable to read the browser session before sending its refreshed cookie, sending none",
					warnings[0].Message)
				assert.ErrorContains(t, warnings[0].Attrs["error"].(error), "database unavailable")
			} else {
				assert.Empty(t, warnings)
			}
		})
	}
}
