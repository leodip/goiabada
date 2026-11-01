package server

// The Turnstile guide held to the routes the challenge guards and the origin their pages admit
// (#642).
//
// The guide is where an administrator learns which forms the challenge is on, and that a
// submission it refuses spends no rate-limit budget. Both are held to the real router, walked as
// the rate-limit table's check walks it: every route mounting one of the Require…Challenge
// middlewares is named in the guide's section, nothing else is, and on each the challenge runs
// before any rate limiter. The origin the guide and the Security page tell an operator the three
// forms admit to their script-src is the one the forms' renders add.

import (
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// turnstileFormsSection is the guide's section naming the forms the challenge is on.
var turnstileFormsSection = docSection{"site/src/content/docs/guides/require-a-turnstile-challenge.mdx", "## The forms it covers"}

// turnstileScriptOriginSections are the sections telling an operator which origin the three
// forms admit to their script-src while the challenge is on.
var turnstileScriptOriginSections = []docSection{
	{"site/src/content/docs/guides/require-a-turnstile-challenge.mdx", "## What it costs"},
	{"site/src/content/docs/reference/security.mdx", "## Response headers"},
}

// challengeMiddlewareName is one of the challenge's middlewares, as the router's Walk names the
// closure its constructor returns: RequirePasswordChallenge's own, or the shared requireChallenge's
// behind the forgot-password and registration forms'. An inlined constructor's closure is named
// .1 rather than .func1.
var challengeMiddlewareName = regexp.MustCompile(`/internal/handlers(?:/accounthandlers)?\.[Rr]equire[A-Za-z]*Challenge\.(?:func)?\d+$`)

// TestTurnstileDocs_TheFormsAreTheRoutesTheChallengeGuards: the guide names exactly the routes
// mounting the challenge, and on each the challenge runs ahead of every rate limiter, so a
// submission it refuses spends no budget, as the guide and the rate-limit rules say.
func TestTurnstileDocs_TheFormsAreTheRoutesTheChallengeGuards(t *testing.T) {
	s := newRoutesTestServer(t)

	var guarded []string
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		challengeAt, firstLimiterAt := -1, -1
		for i, mw := range middlewares {
			name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
			if challengeMiddlewareName.MatchString(name) && challengeAt < 0 {
				challengeAt = i
			}
			if rateLimitMethodName.MatchString(name) && firstLimiterAt < 0 {
				firstLimiterAt = i
			}
		}
		if challengeAt < 0 {
			return nil
		}
		guarded = append(guarded, method+" "+route)
		if firstLimiterAt >= 0 && firstLimiterAt < challengeAt {
			t.Errorf("%s %s mounts a rate limiter ahead of the Turnstile challenge, so a refused "+
				"submission spends budget", method, route)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(guarded) == 0 {
		t.Fatalf("the router walk found no route mounting the Turnstile challenge, so this check asserts nothing")
	}

	section, err := docsreader.Section(filepath.Dir(guard.SourceRoot(t)), turnstileFormsSection.page, turnstileFormsSection.heading)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var documented []string
	for _, span := range docBacktickedSpan.FindAllStringSubmatch(section, -1) {
		if docRouteSpan.MatchString(span[1]) && !slices.Contains(documented, span[1]) {
			documented = append(documented, span[1])
		}
	}

	slices.Sort(guarded)
	slices.Sort(documented)
	if !slices.Equal(guarded, documented) {
		t.Errorf("%s %s names the routes %v, but the challenge guards %v",
			turnstileFormsSection.page, turnstileFormsSection.heading, documented, guarded)
	}
}

// TestTurnstileDocs_ThePagesNameTheOriginTheFormsAdmit: the guide and the Security page name the
// origin the forms' renders add to script-src while the challenge is on, so an operator who sets
// a policy of their own at a proxy admits the one the widget needs.
func TestTurnstileDocs_ThePagesNameTheOriginTheFormsAdmit(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	for _, section := range turnstileScriptOriginSections {
		text, err := docsreader.Section(root, section.page, section.heading)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if !strings.Contains(text, "`"+turnstile.ScriptOrigin+"`") {
			t.Errorf("%s %s does not name %s, the origin the three forms admit to script-src while "+
				"the challenge is on", section.page, section.heading, turnstile.ScriptOrigin)
		}
	}
}
