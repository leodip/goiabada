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
