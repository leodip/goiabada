package server

// The environment-variables page's rate-limit table, held to the rate limiter's tiers and the
// routes they guard (#519).
//
// The table is where an operator learns which endpoint the limiter guards, how many requests or
// failures it allows over which window, and which limiter name the rate_limit_exceeded audit event
// and goiabada_rate_limit_refusals_total carry when it trips. Every tier middleware.NewRateLimiter
// builds is held to it in both directions: a tier with no row fails, and so does a row naming a
// limiter the auth server does not have, or giving one a limit, a window, a counting rule, a
// Counted by cell or an endpoint other than its own. A tier counted on two routes, as the password tiers shared by the
// sign-in form and the password grant are, may take a row per route, and between them they must
// list every route it guards.
//
// The tiers are read from the constructor's source, the one place a tier's limit, window, counting
// rule and the kind of key it counts by are written down, and cross-checked against the limiter label the limiter
// registers its refusal metric with, so a tier the reader cannot see stops the check. The routes
// are the real router's, through chi.Walk over initRoutes, as the routes tests resolve them.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/guard"
)

// rateLimitsSection is the section holding the rate-limit table.
var rateLimitsSection = docSection{"site/src/content/docs/reference/environment-variables.mdx", "## Rate limits"}

// rateLimiterSource is the file declaring NewRateLimiter and the Limit methods.
const rateLimiterSource = "authserver/internal/middleware/middleware_ratelimiter.go"

// rateLimitRefusalsFamily is the metric whose limiter label holds every tier's name.
const rateLimitRefusalsFamily = "goiabada_rate_limit_refusals_total"

// rateLimitTier is one tier as the table is held to it: its name, its budget, whether only a failed
// credential check spends it, the key kind it declares it counts by, as the constant's name, and the
// routes it guards, each as "METHOD /path".
type rateLimitTier struct {
	name         string
	limit        int
	window       time.Duration
	failuresOnly bool
	countedBy    string
	routes       []string
}

// docCountedBy is how the table's Counted by cell writes each key kind a tier can declare (#522
// decision 11). {account} is the word the route names an account by: username on the password grant,
// whose parameter RFC 6749 section 4.3.2 names so, and email on every form. A kind missing here is
// one the table has no words for, which fails the row rather than passing it.
var docCountedBy = map[string]string{
	"countedByIP":            "IP address",
	"countedByAccount":       "{account}",
	"countedByIPAndAccount":  "IP address and {account}",
	"countedBySigningInUser": "user",
	"countedByTokenUser":     "the token's user",
}

// docSharedNote is what may follow a Counted by cell's kind: the routes or grant that share the
// tier's budget, as "email, shared with the password grant".
const docSharedNote = ", shared with "

var (
	// docLimiterCell is a cell holding one backticked limiter name and nothing else.
	docLimiterCell = regexp.MustCompile("^`([a-z][a-z0-9_]*)`$")
	// docBacktickedSpan is any backticked span; the endpoint cell's routes are the spans naming one.
	docBacktickedSpan = regexp.MustCompile("`([^`]*)`")
	// docRouteSpan is a backticked span naming a route, as "POST /auth/pwd".
	docRouteSpan = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) (/\S*)$`)
	// docLimitCell is a count per window, as "10 per 15 minutes" or "30 per minute", which prose
	// after a comma may follow.
	docLimitCell = regexp.MustCompile(`^(\d+) per (?:(\d+) (seconds|minutes|hours)|(second|minute|hour))(?:,.*)?$`)
	// rateLimitMethodName is a Limit method of the rate limiter, as chi.Walk names it.
	rateLimitMethodName = regexp.MustCompile(`/internal/middleware\.\(\*RateLimiter\)\.(Limit[A-Za-z]+)-fm$`)
)

func TestRateLimitsDocs_TheTableIsTheLimitersTiers(t *testing.T) {
	assertRateLimitTable(t, filepath.Dir(guard.SourceRoot(t)), rateLimitsSection, productionRateLimitTiers(t))
}

func TestRateLimitsDocs_ATableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Rate limits\n\n"+
		"| Endpoint | Limiter | Limit | Counts | Counted by |\n"+
		"|---|---|---|---|---|\n"+
		"| `POST /auth/pwd` | `pwd_ip` | 30 per 15 minutes | every request | IP address |\n"+
		"| `POST /auth/pwd` | `pwd_account` | 10 per 60 minutes | failed sign-ins | email |\n"+
		"| `POST /auth/otp` | `otp` | 5 per 15 minutes | every request | user |\n"+
		"| `POST /forgot-password` | `forgot_pwd_ip` | 20 per 5 minutes | failed requests | IP address |\n"+
		"| `POST /forgot-password` and `POST /reset-password` | `forgot_pwd_email` | 5 per 5 minutes | every request | email |\n"+
		"| `POST /forgot-password` | `forgot_pwd_email` | 5 per 5 minutes | every request | email, again |\n"+
		"| `POST /connect/register` | `dcr` | ten a minute | every request | IP address |\n"+
		"| `POST /connect/register` | `dcr_retired` | 10 per minute | every request | IP address |\n"+
		"| the registration endpoint | `register` | 20 per 5 minutes | every request | IP address |\n"+
		"| `POST /account/register` | register_email | 5 per 5 minutes | every request | email |\n"+
		"| `GET /account/activate` | `activate` | 30 per 5 minutes | every request | |\n"+
		"| `POST /auth/token` | `ropc_ip` | 30 per minute | every request |\n"+
		"| `POST /api/v1/account/email/verification` | `email_verification` | 5 per 15 minutes | failed codes | user |\n"+
		"| `POST /auth/token` with `grant_type=password` | `ropc_account` | 100 per 60 minutes | failed sign-ins | email |\n"+
		"| `POST /auth/token` | `ropc_account_net` | 10 per 15 minutes | failed sign-ins | IP address and email, shared with `POST /auth/pwd` |\n"+
		"| `POST /account/register` | `register_address` | 5 per 5 minutes | every request | IP address |\n"+
		"| `GET /reset-password` | `reset_pwd` | 30 per 5 minutes | every request | IP address shared with activate |\n"+
		"| `POST /api/v1/account/email/verification/send` | `send` | 5 per 60 minutes | every request | the token's user |\n\n"+
		"## Next\n\n| `POST /auth/token` | `pwd_account_net` | 10 per 15 minutes | failed sign-ins | IP and email |\n")

	tiers := []rateLimitTier{
		{name: "pwd_ip", limit: 30, window: time.Minute, countedBy: "countedByIP", routes: []string{"POST /auth/pwd"}},
		{name: "pwd_account", limit: 100, window: time.Hour, failuresOnly: true, countedBy: "countedByAccount",
			routes: []string{"POST /auth/pwd", "POST /auth/token"}},
		{name: "pwd_account_net", limit: 10, window: 15 * time.Minute, failuresOnly: true,
			countedBy: "countedByIPAndAccount", routes: []string{"POST /auth/pwd", "POST /auth/token"}},
		{name: "otp", limit: 5, window: 15 * time.Minute, failuresOnly: true, countedBy: "countedBySigningInUser",
			routes: []string{"POST /auth/otp"}},
		{name: "forgot_pwd_ip", limit: 20, window: 5 * time.Minute, countedBy: "countedByIP",
			routes: []string{"POST /forgot-password"}},
		{name: "forgot_pwd_email", limit: 5, window: 5 * time.Minute, countedBy: "countedByAccount",
			routes: []string{"POST /forgot-password"}},
		{name: "dcr", limit: 10, window: time.Minute, countedBy: "countedByIP", routes: []string{"POST /connect/register"}},
		{name: "register", limit: 20, window: 5 * time.Minute, countedBy: "countedByIP",
			routes: []string{"POST /account/register"}},
		{name: "register_email", limit: 5, window: 5 * time.Minute, countedBy: "countedByAccount",
			routes: []string{"POST /account/register"}},
		{name: "activate", limit: 30, window: 5 * time.Minute, countedBy: "countedByIP",
			routes: []string{"GET /account/activate", "POST /account/activate"}},
		{name: "ropc_ip", limit: 30, window: time.Minute, countedBy: "countedByIP", routes: []string{"POST /auth/token"}},
		{name: "email_verification", limit: 5, window: 15 * time.Minute, failuresOnly: true,
			countedBy: "countedByTokenUser", routes: []string{"POST /api/v1/account/email/verification"}},
		{name: "ropc_account", limit: 100, window: time.Hour, failuresOnly: true, countedBy: "countedByAccount",
			routes: []string{"POST /auth/token"}},
		{name: "ropc_account_net", limit: 10, window: 15 * time.Minute, failuresOnly: true,
			countedBy: "countedByIPAndAccount", routes: []string{"POST /auth/token"}},
		{name: "register_address", limit: 5, window: 5 * time.Minute, countedBy: "countedByAccount",
			routes: []string{"POST /account/register"}},
		{name: "reset_pwd", limit: 30, window: 5 * time.Minute, countedBy: "countedByIP",
			routes: []string{"GET /reset-password"}},
		{name: "send", limit: 5, window: time.Hour, countedBy: "countedBySender",
			routes: []string{"POST /api/v1/account/email/verification/send"}},
	}
	report := guard.Run(func(r guard.Reporter) {
		assertRateLimitTable(r, root, docSection{"site/env.mdx", "## Rate limits"}, tiers)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	where := "site/env.mdx: ## Rate limits"
	want := []string{
		where + ` gives pwd_ip the limit "30 per 15 minutes", want "30 per minute"`,
		where + ` gives pwd_account the limit "10 per 60 minutes", want "100 per 60 minutes"`,
		where + " says otp counts every request, but it counts only failed credential checks",
		where + " says forgot_pwd_ip counts failures, but it counts every request",
		where + " gives forgot_pwd_email the endpoint `POST /reset-password`, which it does not guard",
		where + " lists forgot_pwd_email on `POST /forgot-password` twice",
		where + ` says forgot_pwd_email counts by "email, again", want "email"`,
		where + ` gives dcr the limit "ten a minute", want a count per window such as "10 per 15 minutes"`,
		where + " names the limiter dcr_retired, which the auth server does not have",
		where + " gives register no endpoint",
		where + ` has a row whose limiter is not one backticked limiter name: "register_email"`,
		where + " says nothing of what activate counts by",
		where + ` has a row of 4 cells, want endpoint, limiter, limit, counts and counted by: ["` +
			"`POST /auth/token`" + `" "` + "`ropc_ip`" + `" "30 per minute" "every request"]`,
		where + ` says email_verification counts by "user", want "the token's user"`,
		where + ` says ropc_account counts by "email", want "username"`,
		where + ` says ropc_account_net counts by "IP address and email, shared with ` + "`POST /auth/pwd`" +
			`", want "IP address and username"`,
		where + ` says register_address counts by "IP address", want "email"`,
		where + ` says reset_pwd counts by "IP address shared with activate", want "IP address"`,
		where + " gives send the key kind countedBySender, which the table has no words for",
		where + " does not list pwd_account on `POST /auth/token`",
		where + " does not list pwd_account_net",
		where + " does not list register on `POST /account/register`",
		where + " does not list register_email",
		where + " does not list activate on `POST /account/activate`",
		where + " does not list ropc_ip",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestRateLimitsDocs_ATableMatchingTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Rate limits\n\n"+
		"Text before the table.\n\n"+
		"| Endpoint | Limiter | Limit | Counts | Counted by |\n"+
		"|---|---|---|---|---|\n"+
		"| `POST /auth/pwd` (password sign-in) | `pwd_account` | 100 per 60 minutes | failed sign-ins | email, shared with the password grant |\n"+
		"| `POST /auth/pwd` | `pwd_account_net` | 10 per 15 minutes | failed sign-ins | IP address and email |\n"+
		"| `POST /auth/pwd` | `pwd_ip` | 30 per minute | every request | IP address |\n"+
		"| `POST /auth/otp` | `otp` | 5 per 15 minutes | failed codes | user |\n"+
		"| `PUT /api/v1/account/password` and `PUT /api/v1/account/otp` | `account_password` | 5 per 15 minutes, for the two together | failed passwords | the token's user |\n"+
		"| `GET /reset-password` and `POST /reset-password` | `reset_pwd` | 30 per 5 minutes | every request | IP address |\n"+
		"| `POST /auth/token` with `grant_type=password` | `pwd_account` | 100 per hour | failed sign-ins | username, shared with `POST /auth/pwd` |\n"+
		"| `POST /auth/token` | `pwd_account_net` | 10 per 15 minutes | failed sign-ins | IP address and username, shared with `POST /auth/pwd` |\n"+
		"| `POST /forgot-password` | `forgot_pwd_email` | 5 per 5 minutes | every request | email |\n"+
		"| `POST /connect/register` | `dcr` | 10 per 60 seconds | every request | IP address |\n\n"+
		"- A rule after the table.\n\n"+
		"## Next\n\nText.\n")

	tiers := []rateLimitTier{
		{name: "pwd_account", limit: 100, window: time.Hour, failuresOnly: true, countedBy: "countedByAccount",
			routes: []string{"POST /auth/pwd", "POST /auth/token"}},
		{name: "pwd_account_net", limit: 10, window: 15 * time.Minute, failuresOnly: true,
			countedBy: "countedByIPAndAccount", routes: []string{"POST /auth/pwd", "POST /auth/token"}},
		{name: "pwd_ip", limit: 30, window: time.Minute, countedBy: "countedByIP", routes: []string{"POST /auth/pwd"}},
		{name: "otp", limit: 5, window: 15 * time.Minute, failuresOnly: true, countedBy: "countedBySigningInUser",
			routes: []string{"POST /auth/otp"}},
		{name: "account_password", limit: 5, window: 15 * time.Minute, failuresOnly: true,
			countedBy: "countedByTokenUser", routes: []string{"PUT /api/v1/account/otp", "PUT /api/v1/account/password"}},
		{name: "reset_pwd", limit: 30, window: 5 * time.Minute, countedBy: "countedByIP",
			routes: []string{"GET /reset-password", "POST /reset-password"}},
		{name: "forgot_pwd_email", limit: 5, window: 5 * time.Minute, countedBy: "countedByAccount",
			routes: []string{"POST /forgot-password"}},
		{name: "dcr", limit: 10, window: time.Minute, countedBy: "countedByIP", routes: []string{"POST /connect/register"}},
	}
	report := guard.Run(func(r guard.Reporter) {
		assertRateLimitTable(r, root, docSection{"site/env.mdx", "## Rate limits"}, tiers)
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table matching the code failed: %+v", report)
	}
}

func TestRateLimitsDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Limits\n\n"+
		"| Endpoint | Limiter | Limit | Counts | Counted by |\n|---|---|---|---|---|\n"+
		"| `POST /connect/register` | `dcr` | 10 per minute | every request | IP address |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRateLimitTable(r, root, docSection{"site/env.mdx", "## Rate limits"},
			[]rateLimitTier{{name: "dcr", limit: 10, window: time.Minute, routes: []string{"POST /connect/register"}}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Rate limits") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestRateLimitsDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Rate limits\n\n- `POST /connect/register`: 10 per minute.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRateLimitTable(r, root, docSection{"site/env.mdx", "## Rate limits"},
			[]rateLimitTier{{name: "dcr", limit: 10, window: time.Minute, routes: []string{"POST /connect/register"}}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

func TestRateLimitsDocs_NoTiersStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/env.mdx", "## Rate limits\n\n"+
		"| Endpoint | Limiter | Limit | Counts | Counted by |\n|---|---|---|---|---|\n"+
		"| `POST /connect/register` | `dcr` | 10 per minute | every request | IP address |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRateLimitTable(r, root, docSection{"site/env.mdx", "## Rate limits"}, nil)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no tier") {
		t.Errorf("a check handed no tiers did not stop: %+v", report)
	}
}

// TestRateLimiterSourceTiers_ReadsTheConstructorAndTheLimitMethods holds the reader to a source of
// every shape the constructor writes a tier in: a request tier, a failures-only tier, the two
// failures-only tiers an account limiter pairs, a window written bare, in minutes and in hours,
// and a Limit method reaching its tiers directly and through a helper's argument.
func TestRateLimiterSourceTiers_ReadsTheConstructorAndTheLimitMethods(t *testing.T) {
	src := `package middleware

import "time"

func NewRateLimiter(store any) *RateLimiter {
	request := func(name string, counted countedBy, keyField string, limit int, window time.Duration) *requestTier { return nil }
	failure := func(name string, counted countedBy, limit int, window time.Duration) *failureTier { return nil }
	m := &RateLimiter{
		store: store,
		pwdAccount: newAccountTiers(failure("pwd_account_net", countedByIPAndAccount, 10, 15*time.Minute),
			failure("pwd_account", countedByAccount, 100, 60*time.Minute)),
		pwdIp: request("pwd_ip", countedByIP, "ip", 30, time.Minute),
		otp:   failure("otp", countedBySigningInUser, 5, 15*time.Minute),
		dcr:   request("dcr", countedByIP, "ip", 10, 2*time.Hour),
	}
	return m
}

func (m *RateLimiter) LimitPwd(next any) any {
	_ = m.pwdIp
	_ = m.pwdAccount
	_ = m.store
	return next
}

func (rl *RateLimiter) LimitOtp(next any) any { return rl.limitFailures(next, rl.otp) }

func (m *RateLimiter) limitFailures(next any, t *failureTier) any { _ = m.dcr; return next }

func (m *RateLimiter) LimitDCR(next any) any { return m.limitFailures(next, m.dcr) }
`
	read, err := rateLimiterSourceTiers("fixture.go", []byte(src))
	if err != nil {
		t.Fatalf("the reader refused the fixture: %v", err)
	}

	wantTiers := []rateLimitTier{
		{name: "pwd_account_net", limit: 10, window: 15 * time.Minute, failuresOnly: true, countedBy: "countedByIPAndAccount"},
		{name: "pwd_account", limit: 100, window: time.Hour, failuresOnly: true, countedBy: "countedByAccount"},
		{name: "pwd_ip", limit: 30, window: time.Minute, countedBy: "countedByIP"},
		{name: "otp", limit: 5, window: 15 * time.Minute, failuresOnly: true, countedBy: "countedBySigningInUser"},
		{name: "dcr", limit: 10, window: 2 * time.Hour, countedBy: "countedByIP"},
	}
	if !reflect.DeepEqual(read.tiers, wantTiers) {
		t.Errorf("tiers\n%+v\nwant\n%+v", read.tiers, wantTiers)
	}
	wantMethods := map[string][]string{
		"LimitPwd": {"pwd_ip", "pwd_account_net", "pwd_account"},
		"LimitOtp": {"otp"},
		"LimitDCR": {"dcr"},
	}
	if !reflect.DeepEqual(read.methods, wantMethods) {
		t.Errorf("methods\n%v\nwant\n%v", read.methods, wantMethods)
	}
}

// TestRateLimiterSourceTiers_RefusesWhatItCannotRead is the reader stopping rather than skipping:
// a window or a limit it cannot evaluate, a key kind that is not a constant's name, a builder called
// with the arguments of another shape, a Limit method reaching no tier, and a source with no
// constructor.
func TestRateLimiterSourceTiers_RefusesWhatItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a window written as a variable",
			src: `package middleware
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{otp: failure("otp", countedBySigningInUser, 5, otpWindow)}
}
func (m *RateLimiter) LimitOtp(next any) any { _ = m.otp; return next }
`,
			want: "cannot read the window of the tier otp: otpWindow",
		},
		{
			name: "a limit written as a constant",
			src: `package middleware
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{otp: failure("otp", countedBySigningInUser, otpLimit, time.Minute)}
}
`,
			want: "cannot read the limit of the tier otp: otpLimit",
		},
		{
			name: "a key kind written as a call",
			src: `package middleware
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{otp: failure("otp", kindOf("otp"), 5, time.Minute)}
}
`,
			want: `cannot read what the tier otp counts by: kindOf("otp")`,
		},
		{
			name: "a request tier built with no key kind",
			src: `package middleware
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{dcr: request("dcr", "ip", 10, time.Minute)}
}
`,
			want: "request is called with 4 arguments, want 5",
		},
		{
			name: "a Limit method reaching no tier",
			src: `package middleware
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{otp: failure("otp", countedBySigningInUser, 5, time.Minute)}
}
func (m *RateLimiter) LimitOtp(next any) any { return next }
`,
			want: "LimitOtp reaches no tier",
		},
		{
			name: "no constructor",
			src:  "package middleware\n",
			want: "declares no tier",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := rateLimiterSourceTiers("fixture.go", []byte(c.src))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}

// productionRateLimitTiers is every tier NewRateLimiter builds, with the routes initRoutes mounts
// it on. It stops the test when the reader's tiers are not exactly the limiter label's values, when
// a route mounts a Limit method the reader did not find, or when no route mounts one at all.
func productionRateLimitTiers(t *testing.T) []rateLimitTier {
	t.Helper()

	path := filepath.Join(guard.SourceRoot(t), filepath.FromSlash(rateLimiterSource))
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", rateLimiterSource, err)
	}
	read, err := rateLimiterSourceTiers(rateLimiterSource, src)
	if err != nil {
		t.Fatalf("%v", err)
	}

	s := newRoutesTestServer(t)

	var labelled []string
	for _, family := range s.metrics.Families() {
		if family.Name != rateLimitRefusalsFamily {
			continue
		}
		for _, label := range family.Labels {
			if label.Name() == "limiter" {
				labelled = label.Values()
			}
		}
	}
	var names []string
	for _, tier := range read.tiers {
		names = append(names, tier.name)
	}
	if !slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(slices.Values(labelled))) {
		t.Fatalf("%s declares the tiers %v, but %s's limiter label holds %v; a tier the reader does not see "+
			"would go unchecked", rateLimiterSource, names, rateLimitRefusalsFamily, labelled)
	}

	byName := make(map[string]*rateLimitTier, len(read.tiers))
	for i := range read.tiers {
		byName[read.tiers[i].name] = &read.tiers[i]
	}
	mounted := 0
	err = chi.Walk(s.router, func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		for _, mw := range middlewares {
			match := rateLimitMethodName.FindStringSubmatch(runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name())
			if match == nil {
				continue
			}
			tierNames, ok := read.methods[match[1]]
			if !ok {
				return fmt.Errorf("%s %s mounts %s, which %s does not declare as reaching a tier",
					method, route, match[1], rateLimiterSource)
			}
			mounted++
			for _, name := range tierNames {
				byName[name].routes = append(byName[name].routes, method+" "+route)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if mounted == 0 {
		t.Fatalf("chi.Walk found no route mounting a rate limiter, so this check asserts nothing")
	}
	return read.tiers
}

// rateLimiterTiers is what rateLimiterSourceTiers reads: every tier, in the order the constructor
// declares it, and the tiers each Limit method reaches, in the order it first names them.
type rateLimiterTiers struct {
	tiers   []rateLimitTier
	methods map[string][]string
}

// rateLimiterSourceTiers reads the tiers out of NewRateLimiter's RateLimiter literal, each built by
// request(name, countedBy, keyField, limit, window) or failure(name, countedBy, limit, window),
// directly or as an argument of another call such as newAccountTiers, and the tiers each exported
// Limit method on *RateLimiter reaches through its receiver's fields. It refuses a tier whose name,
// limit or window is not written as a literal or whose key kind is not a constant's name, a Limit
// method reaching no tier, and a source declaring none.
func rateLimiterSourceTiers(filename string, src []byte) (rateLimiterTiers, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return rateLimiterTiers{}, err
	}

	read := rateLimiterTiers{methods: map[string][]string{}}
	fieldTiers := map[string][]string{}
	var readErr error
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "NewRateLimiter" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || readErr != nil {
				return readErr == nil
			}
			if ident, ok := lit.Type.(*ast.Ident); !ok || ident.Name != "RateLimiter" {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				field, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				tiers, err := tiersBuiltBy(kv.Value)
				if err != nil {
					readErr = fmt.Errorf("%s: %w", filename, err)
					return false
				}
				for _, tier := range tiers {
					read.tiers = append(read.tiers, tier)
					fieldTiers[field.Name] = append(fieldTiers[field.Name], tier.name)
				}
			}
			return false
		})
	}
	if readErr != nil {
		return rateLimiterTiers{}, readErr
	}
	if len(read.tiers) == 0 {
		return rateLimiterTiers{}, fmt.Errorf("%s declares no tier in a NewRateLimiter RateLimiter literal", filename)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isRateLimiterMethod(fn) || !strings.HasPrefix(fn.Name.Name, "Limit") || !fn.Name.IsExported() {
			continue
		}
		receiver := fn.Recv.List[0].Names
		if len(receiver) == 0 {
			return rateLimiterTiers{}, fmt.Errorf("%s: %s names no receiver", filename, fn.Name.Name)
		}
		var reached []string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == receiver[0].Name {
				for _, name := range fieldTiers[sel.Sel.Name] {
					if !slices.Contains(reached, name) {
						reached = append(reached, name)
					}
				}
			}
			return true
		})
		if len(reached) == 0 {
			return rateLimiterTiers{}, fmt.Errorf("%s: %s reaches no tier", filename, fn.Name.Name)
		}
		read.methods[fn.Name.Name] = reached
	}
	return read, nil
}

// isRateLimiterMethod reports whether fn is declared on *RateLimiter.
func isRateLimiterMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "RateLimiter"
}

// tiersBuiltBy is the tiers expr builds: one for a call of request or failure, those of its
// arguments for any other call, and none for anything else.
func tiersBuiltBy(expr ast.Expr) ([]rateLimitTier, error) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	if ident, ok := call.Fun.(*ast.Ident); ok && (ident.Name == "request" || ident.Name == "failure") {
		tier, err := tierBuiltBy(ident.Name, call.Args)
		if err != nil {
			return nil, err
		}
		return []rateLimitTier{tier}, nil
	}
	var tiers []rateLimitTier
	for _, arg := range call.Args {
		built, err := tiersBuiltBy(arg)
		if err != nil {
			return nil, err
		}
		tiers = append(tiers, built...)
	}
	return tiers, nil
}

// tierBuiltBy reads request(name, countedBy, keyField, limit, window) or
// failure(name, countedBy, limit, window).
func tierBuiltBy(builder string, args []ast.Expr) (rateLimitTier, error) {
	limitAt, want := 3, 5
	if builder == "failure" {
		limitAt, want = 2, 4
	}
	if len(args) != want {
		return rateLimitTier{}, fmt.Errorf("%s is called with %d arguments, want %d", builder, len(args), want)
	}
	nameLit, ok := args[0].(*ast.BasicLit)
	if !ok || nameLit.Kind != token.STRING {
		return rateLimitTier{}, fmt.Errorf("cannot read the name of a tier: %s", types.ExprString(args[0]))
	}
	name, err := strconv.Unquote(nameLit.Value)
	if err != nil {
		return rateLimitTier{}, err
	}
	counted, ok := args[1].(*ast.Ident)
	if !ok {
		return rateLimitTier{}, fmt.Errorf("cannot read what the tier %s counts by: %s", name, types.ExprString(args[1]))
	}
	limit, ok := intLiteral(args[limitAt])
	if !ok {
		return rateLimitTier{}, fmt.Errorf("cannot read the limit of the tier %s: %s", name, types.ExprString(args[limitAt]))
	}
	window, ok := durationLiteral(args[limitAt+1])
	if !ok {
		return rateLimitTier{}, fmt.Errorf("cannot read the window of the tier %s: %s", name, types.ExprString(args[limitAt+1]))
	}
	return rateLimitTier{name: name, limit: limit, window: window, failuresOnly: builder == "failure",
		countedBy: counted.Name}, nil
}

// intLiteral is the value of an integer literal.
func intLiteral(expr ast.Expr) (int, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	return n, err == nil
}

// durationLiteral is the value of time.Second, time.Minute or time.Hour, alone or multiplied by an
// integer literal.
func durationLiteral(expr ast.Expr) (time.Duration, bool) {
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.MUL {
		if n, ok := intLiteral(bin.X); ok {
			unit, ok := durationLiteral(bin.Y)
			return time.Duration(n) * unit, ok
		}
		if n, ok := intLiteral(bin.Y); ok {
			unit, ok := durationLiteral(bin.X)
			return time.Duration(n) * unit, ok
		}
		return 0, false
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "time" {
		return 0, false
	}
	switch sel.Sel.Name {
	case "Second":
		return time.Second, true
	case "Minute":
		return time.Minute, true
	case "Hour":
		return time.Hour, true
	}
	return 0, false
}

// assertRateLimitTable is the reporting half of the check: one failure per finding of
// rateLimitTableFindings; a stop for no tiers, a section not found or one holding no table, since
// a check that compared nothing proves nothing.
func assertRateLimitTable(r guard.Reporter, root string, section docSection, tiers []rateLimitTier) {
	r.Helper()
	findings, err := rateLimitTableFindings(root, section, tiers)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// rateLimitTableFindings reads the section's table, one row per limiter and endpoint with its
// limit, what it counts and what it counts by, and returns one finding per row that is malformed,
// names a limiter the auth server does not have, names no endpoint or one its limiter does not
// guard, lists a limiter on an endpoint a second time, gives a limiter a limit, a window or a
// counting rule other than its own, says nothing of what it counts by or counts it by other than the
// key kind the tier declares, or gives a tier a kind the table has no words for; then one per tier with no
// row, or with no row for a route it guards. It returns an error, and no findings, for no tiers, or
// a section not found or holding no table.
func rateLimitTableFindings(root string, section docSection, tiers []rateLimitTier) ([]string, error) {
	if len(tiers) == 0 {
		return nil, fmt.Errorf("%s: %s was handed no tier to hold its table to", section.page, section.heading)
	}
	text, err := docSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := docTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table of the rate limits", section.page, section.heading)
	}

	byName := make(map[string]rateLimitTier, len(tiers))
	for _, tier := range tiers {
		byName[tier.name] = tier
	}

	where := section.page + ": " + section.heading
	var findings []string
	listed := make(map[string]map[string]bool)
	for _, cells := range rows {
		if len(cells) != 5 {
			findings = append(findings, fmt.Sprintf("%s has a row of %d cells, want endpoint, limiter, limit, counts and counted by: %q",
				where, len(cells), cells))
			continue
		}
		endpointCell, limiterCell, limitCell, countsCell, keyCell := cells[0], cells[1], cells[2], cells[3], cells[4]
		match := docLimiterCell.FindStringSubmatch(limiterCell)
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose limiter is not one backticked limiter name: %q",
				where, limiterCell))
			continue
		}
		name := match[1]
		tier, ok := byName[name]
		if !ok {
			findings = append(findings, where+" names the limiter "+name+", which the auth server does not have")
			continue
		}
		if listed[name] == nil {
			listed[name] = make(map[string]bool)
		}

		var routes []string
		for _, span := range docBacktickedSpan.FindAllStringSubmatch(endpointCell, -1) {
			if docRouteSpan.MatchString(span[1]) {
				routes = append(routes, span[1])
			}
		}
		if len(routes) == 0 {
			findings = append(findings, where+" gives "+name+" no endpoint")
		}
		for _, route := range routes {
			switch {
			case !slices.Contains(tier.routes, route):
				findings = append(findings, where+" gives "+name+" the endpoint `"+route+"`, which it does not guard")
			case listed[name][route]:
				findings = append(findings, where+" lists "+name+" on `"+route+"` twice")
			default:
				listed[name][route] = true
			}
		}

		if limit, window, ok := docLimit(limitCell); !ok {
			findings = append(findings, fmt.Sprintf("%s gives %s the limit %q, want a count per window such as %q",
				where, name, limitCell, "10 per 15 minutes"))
		} else if limit != tier.limit || window != tier.window {
			findings = append(findings, fmt.Sprintf("%s gives %s the limit %q, want %q",
				where, name, limitCell, docLimitText(tier.limit, tier.window)))
		}

		switch {
		case countsCell == "every request":
			if tier.failuresOnly {
				findings = append(findings, where+" says "+name+" counts every request, but it counts only failed credential checks")
			}
		case strings.HasPrefix(countsCell, "failed "):
			if !tier.failuresOnly {
				findings = append(findings, where+" says "+name+" counts failures, but it counts every request")
			}
		default:
			findings = append(findings, fmt.Sprintf("%s gives %s the count %q, want %q or failures such as %q",
				where, name, countsCell, "every request", "failed sign-ins"))
		}

		if keyCell == "" {
			findings = append(findings, where+" says nothing of what "+name+" counts by")
		} else if finding := docCountedByFinding(keyCell, tier, routes); finding != "" {
			findings = append(findings, where+finding)
		}
	}
	for _, tier := range tiers {
		if listed[tier.name] == nil {
			findings = append(findings, where+" does not list "+tier.name)
			continue
		}
		for _, route := range tier.routes {
			if !listed[tier.name][route] {
				findings = append(findings, where+" does not list "+tier.name+" on `"+route+"`")
			}
		}
	}
	return findings, nil
}

// docCountedByFinding is what is wrong with a row's Counted by cell for tier, whose row names
// routes, or "" when nothing is: the cell must be the words docCountedBy gives the tier's key kind,
// with the account named as the route names it, optionally followed by a note of what shares the
// budget.
func docCountedByFinding(cell string, tier rateLimitTier, routes []string) string {
	words, ok := docCountedBy[tier.countedBy]
	if !ok {
		return " gives " + tier.name + " the key kind " + tier.countedBy + ", which the table has no words for"
	}
	account := "email"
	if slices.Contains(routes, "POST /auth/token") {
		account = "username"
	}
	want := strings.ReplaceAll(words, "{account}", account)
	kind, _, _ := strings.Cut(cell, docSharedNote)
	if kind != want {
		return fmt.Sprintf(" says %s counts by %q, want %q", tier.name, cell, want)
	}
	return ""
}

// docLimit reads a limit cell: the count, and the window it is spent over.
func docLimit(cell string) (int, time.Duration, bool) {
	match := docLimitCell.FindStringSubmatch(cell)
	if match == nil {
		return 0, 0, false
	}
	limit, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, 0, false
	}
	n, unit := 1, match[4]
	if match[2] != "" {
		if n, err = strconv.Atoi(match[2]); err != nil {
			return 0, 0, false
		}
		unit = strings.TrimSuffix(match[3], "s")
	}
	units := map[string]time.Duration{"second": time.Second, "minute": time.Minute, "hour": time.Hour}
	return limit, time.Duration(n) * units[unit], true
}

// docLimitText is how the page writes a limit: per minute, per 15 minutes, per 60 minutes.
func docLimitText(limit int, window time.Duration) string {
	unit, n := "minute", int(window/time.Minute)
	if window%time.Minute != 0 {
		unit, n = "second", int(window/time.Second)
	}
	if n == 1 {
		return fmt.Sprintf("%d per %s", limit, unit)
	}
	return fmt.Sprintf("%d per %d %ss", limit, n, unit)
}

// docSection is a page, as a path from the repository root, and the heading of the section read.
type docSection struct {
	page    string
	heading string
}

// docSectionText is the section's text, without its heading line: from the line after the heading
// to the next heading of the same level or above. A line inside a code fence is never a heading,
// so a shell comment in an example does not end the section.
func docSectionText(root string, section docSection) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.page)))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", section.page, err)
	}
	level := docHeadingLevel(section.heading)
	var body []string
	inFence, inSection := false, false
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if !inFence {
			if inSection {
				if headingLevel := docHeadingLevel(line); headingLevel > 0 && headingLevel <= level {
					return strings.Join(body, "\n"), nil
				}
			} else if strings.TrimRight(line, " \r") == section.heading {
				inSection = true
				continue
			}
		}
		if inSection {
			body = append(body, line)
		}
	}
	if !inSection {
		return "", fmt.Errorf("%s has no section headed %q", section.page, section.heading)
	}
	return strings.Join(body, "\n"), nil
}

// docHeadingLevel is the number of #s a Markdown heading line opens with, or 0 for any other line.
func docHeadingLevel(line string) int {
	level := len(line) - len(strings.TrimLeft(line, "#"))
	if level == 0 || !strings.HasPrefix(line[level:], " ") {
		return 0
	}
	return level
}

// docTableRows is the body rows of the first Markdown table in text, each trimmed cell in order:
// the header row and the delimiter row under it are left out.
func docTableRows(text string) [][]string {
	var rows [][]string
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if !inTable {
			inTable = true // the header row
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the delimiter row
		}
		rows = append(rows, cells)
	}
	return rows
}

// writeDocFixture writes content to root/name, creating its directory.
func writeDocFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
