package server

// The one place the administrative policy is held to covering the whole admin API.
//
// The admin API's route gate asks whether a token may call a route; the administrative policy in
// internal/handlers/apihandlers asks whether it may do what the request does, to whom (#402
// decision 1). The policy is applied by each handler calling a ceiling, so a write route added
// later, whose handler calls none, would let every granular scope reaching it write to
// administrators again, and nothing would go red: the route gate admits it, and no test of the
// policy knows the route exists. That is the defect #402 is.
//
// So every admin write route is classified here, by the ceilings its handler applies or by why it
// needs none, and the classification is held to the code in both directions: a write route with
// no row fails, a row naming no route fails, and a row naming other ceilings than its handler
// applies fails. A read that applies a ceiling, the client secret's, is held to a row too.
//
// It reads and parses files and nothing else: no database, no git, no network.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three ceilings a row can name, spelled as the policy's refusal records them (#402 decisions
// 1, 5 and 7).
const (
	adminCeilingGrant    = "grant"
	adminCeilingTarget   = "target"
	adminCeilingSettings = "settings"
)

// adminPolicyCeilings is every function in the handler package that applies a ceiling, and the
// ceiling it applies. A handler applies a ceiling when it calls one of these, directly or through
// a function of its own package. A function that answers a refusal and is not listed here fails the
// guard, so a new ceiling is added here rather than going uncounted.
var adminPolicyCeilings = map[string]string{
	"grantCeilingAllows":         adminCeilingGrant,
	"membershipCeilingAllows":    adminCeilingGrant,
	"userGroupsCeilingAllows":    adminCeilingGrant,
	"groupDeletionCeilingAllows": adminCeilingGrant,
	"userTargetCeilingAllows":    adminCeilingTarget,
	"groupTargetCeilingAllows":   adminCeilingTarget,
	"clientTargetCeilingAllows":  adminCeilingTarget,
	"settingsCeilingAllows":      adminCeilingSettings,
}

// adminPolicyRefusal is the function every ceiling answers a refusal through.
const adminPolicyRefusal = "refuseAdministratorChange"

// The tree the guard reads, relative to the source root, forward slashes.
const (
	adminRoutesFile       = "authserver/internal/server/routes.go"
	adminHandlersDir      = "authserver/internal/handlers/apihandlers"
	adminHandlersPackage  = "apihandlers"
	adminRoutePrefix      = "/api/v1/admin/"
	adminRouteGroupPrefix = "/api/v1/admin"
)

// adminRouteClass is how the policy classifies one admin route: by the ceilings its handler
// applies, or, for a route applying none, by why it needs none. A row has one or the other.
type adminRouteClass struct {
	ceilings []string
	outside  string
}

// appliesCeilings classifies a route by the ceilings its handler applies.
func appliesCeilings(ceilings ...string) adminRouteClass {
	return adminRouteClass{ceilings: ceilings}
}

// outsideCeilings classifies a route whose handler applies no ceiling, saying why it needs none.
func outsideCeilings(why string) adminRouteClass {
	return adminRouteClass{outside: why}
}

// adminRouteClassification is the classification of every admin write route, and of every admin
// read whose handler applies a ceiling, keyed by method and pattern as routes.go registers them.
//
// A write on an administrator user, group or client meets the target ceiling, and one that grants
// or revokes an administrative permission, directly or through a group, meets the grant ceiling
// too (#402 decision 1). The email and audit-log settings meet the settings ceiling (#402 decision
// 7). What is outside every ceiling says why: creating a principal, which is never an
// administrator, a resource or permission conferring no power in this server, or a setting that
// changes posture and gives the caller no authority it lacks.
var adminRouteClassification = map[string]adminRouteClass{
	// Users.
	"PUT /api/v1/admin/users/{id}/enabled":                  appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/profile":                  appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/address":                  appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/email":                    appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/users/{id}/email/verification-code": appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/phone":                    appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/password":                 appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/otp":                      appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/users/{id}/profile-picture":         appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/users/{id}/profile-picture":       appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/users/{id}":                       appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/user-attributes":                    appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/user-attributes/{id}":                appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/user-attributes/{id}":             appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/user-sessions/{id}":               appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/user-consents/{id}":               appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/groups":                   appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"PUT /api/v1/admin/users/{id}/permissions":              appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"POST /api/v1/admin/users/create": outsideCeilings("creates a user, granted only manage-account, which is not " +
		"administrative: a new user is never an administrator"),

	// Groups.
	"PUT /api/v1/admin/groups/{id}":                     appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/groups/{id}":                  appliesCeilings(adminCeilingGrant),
	"POST /api/v1/admin/groups/{id}/members":            appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"DELETE /api/v1/admin/groups/{id}/members/{userId}": appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"POST /api/v1/admin/group-attributes":               appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/group-attributes/{id}":           appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/group-attributes/{id}":        appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/groups/{id}/permissions":         appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"POST /api/v1/admin/groups": outsideCeilings("creates a group, which holds no permission: a new group is never " +
		"an administrator"),

	// Clients. Reading a secret is the one read a ceiling guards (#402 decision 8).
	"GET /api/v1/admin/clients/{id}/secret":         appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}":                appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/authentication": appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/oauth2-flows":   appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/redirect-uris":  appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/web-origins":    appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/tokens":         appliesCeilings(adminCeilingTarget),
	"PUT /api/v1/admin/clients/{id}/permissions":    appliesCeilings(adminCeilingGrant, adminCeilingTarget),
	"DELETE /api/v1/admin/clients/{id}":             appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/clients/{id}/logo":          appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/clients/{id}/logo":        appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/clients": outsideCeilings("creates a client, which holds no permission: a new client is " +
		"never an administrator"),

	// Resources and their permissions.
	"POST /api/v1/admin/resources": outsideCeilings("creates a resource, whose permissions confer no power in " +
		"this server"),
	"PUT /api/v1/admin/resources/{id}": outsideCeilings("the authserver resource's identifier cannot be changed, " +
		"and no other resource's permissions confer power in this server"),
	"DELETE /api/v1/admin/resources/{id}": outsideCeilings("the authserver resource cannot be deleted, and no " +
		"other resource's permissions confer power in this server"),
	"PUT /api/v1/admin/resources/{resourceId}/permissions": outsideCeilings("the built-in authserver permissions " +
		"cannot be renamed or deleted, and a permission added beside them confers no power in this server " +
		"(#402 decision 2)"),

	// Settings.
	"PUT /api/v1/admin/settings/email":      appliesCeilings(adminCeilingSettings),
	"PUT /api/v1/admin/settings/audit-logs": appliesCeilings(adminCeilingSettings),
	"POST /api/v1/admin/settings/email/send-test": outsideCeilings("sends one message through the stored SMTP " +
		"settings and changes none of them"),
	"PUT /api/v1/admin/settings/general": outsideCeilings("changes posture and gives the caller no authority it " +
		"lacks (#402 decision 7)"),
	"PUT /api/v1/admin/settings/sessions": outsideCeilings("changes posture and gives the caller no authority it " +
		"lacks (#402 decision 7)"),
	"PUT /api/v1/admin/settings/ui-theme": outsideCeilings("changes how pages look and gives the caller no " +
		"authority it lacks (#402 decision 7)"),
	"PUT /api/v1/admin/settings/tokens": outsideCeilings("changes posture and gives the caller no authority it " +
		"lacks (#402 decision 7)"),
	"POST /api/v1/admin/settings/keys/rotate": outsideCeilings("rotates the signing keys, which can deny " +
		"service and gives the caller no authority it lacks (#402 decision 7)"),
	"DELETE /api/v1/admin/settings/keys/{id}": outsideCeilings("deletes a previous signing key, which can deny " +
		"service and gives the caller no authority it lacks (#402 decision 7)"),
}

// adminRouteFinding is one way the classification and the code disagree.
type adminRouteFinding struct {
	// route is METHOD pattern, or the function's name for an unlisted ceiling.
	route  string
	reason string
}

// findAdminRouteClassificationGaps reads root's routes.go and handler package and reports every
// admin route the classification does not hold: a write route, or a route whose handler applies a
// ceiling, with no row; a row naming no admin route; a row naming other ceilings than its handler
// applies, or malformed; an admin route whose handler is not a function the handler package
// declares; and a function answering a refusal that adminPolicyCeilings does not list. It also
// returns how many admin routes and handler files it read, so the reporting half can tell "nothing
// to report" from "nothing was read".
func findAdminRouteClassificationGaps(
	root string, classification map[string]adminRouteClass, ceilings map[string]string,
) (found []adminRouteFinding, routes, files int, err error) {
	routesPath := filepath.Join(root, filepath.FromSlash(adminRoutesFile))
	fset := token.NewFileSet()
	routesSource, err := parser.ParseFile(fset, routesPath, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, 0, err
	}
	var registered []routeRegistration
	collectRoutes(fset, routesSource, "", false, &registered)

	applied, unlisted, files, err := adminHandlerCeilings(filepath.Join(root, filepath.FromSlash(adminHandlersDir)), ceilings)
	if err != nil {
		return nil, 0, 0, err
	}
	for _, name := range unlisted {
		found = append(found, adminRouteFinding{route: name, reason: "answers a refusal through " + adminPolicyRefusal +
			", but adminPolicyCeilings does not list it as a ceiling"})
	}

	seen := map[string]bool{}
	for _, registration := range registered {
		if !strings.HasPrefix(registration.path, adminRoutePrefix) {
			continue
		}
		routes++
		route := strings.ToUpper(registration.method) + " " + registration.path
		seen[route] = true
		class, classified := classification[route]

		handler, inPackage := strings.CutPrefix(registration.handler, adminHandlersPackage+".")
		handlerCeilings, declared := applied[handler]
		if !inPackage || !declared {
			found = append(found, adminRouteFinding{route: route, reason: "its handler " + registration.handler +
				" is not a function " + adminHandlersPackage + " declares, so what it applies cannot be read"})
			continue
		}

		write := registration.method != "get" && registration.method != "head" && registration.method != "options"
		switch {
		case !classified && write:
			found = append(found, adminRouteFinding{route: route, reason: "a write route the policy does not classify; its handler applies " +
				describeCeilings(handlerCeilings)})
		case !classified && len(handlerCeilings) > 0:
			found = append(found, adminRouteFinding{route: route, reason: "a route applying " + describeCeilings(handlerCeilings) +
				" the policy does not classify"})
		case classified:
			if reason := adminRouteRowDisagrees(class, handlerCeilings); reason != "" {
				found = append(found, adminRouteFinding{route: route, reason: reason})
			}
		}
	}

	stale := make([]string, 0)
	for route := range classification {
		if !seen[route] {
			stale = append(stale, route)
		}
	}
	sort.Strings(stale)
	for _, route := range stale {
		found = append(found, adminRouteFinding{route: route, reason: "classified, but routes.go registers no such admin route"})
	}
	return found, routes, files, nil
}

// adminRouteRowDisagrees is why a route's row does not hold its handler, or empty when it does.
func adminRouteRowDisagrees(class adminRouteClass, applied []string) string {
	switch {
	case len(class.ceilings) == 0 && class.outside == "":
		return "a row names its ceilings or why it needs none, and this names neither"
	case len(class.ceilings) > 0 && class.outside != "":
		return "a row names its ceilings or why it needs none, and this names both"
	}
	for _, ceiling := range class.ceilings {
		if ceiling != adminCeilingGrant && ceiling != adminCeilingTarget && ceiling != adminCeilingSettings {
			return "names \"" + ceiling + "\", which is no ceiling"
		}
	}

	named := sortedCeilings(class.ceilings)
	if slices.Equal(named, applied) {
		return ""
	}
	if len(named) == 0 {
		return "classified as outside the ceilings, but its handler applies " + describeCeilings(applied)
	}
	return "classified as applying " + describeCeilings(named) + ", but its handler applies " + describeCeilings(applied)
}

// adminHandlerCeilings reads the production files of the handler package in dir and returns, for
// every package-level function it declares, the ceilings it applies, sorted and each once: those it
// calls, and those every function of the package it calls applies. A call to a ceiling counts as
// that ceiling and is not followed further. It also returns, sorted, every function calling the
// refusal that ceilings does not list, and how many files it read.
func adminHandlerCeilings(dir string, ceilings map[string]string) (applied map[string][]string, unlisted []string, files int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, 0, err
	}

	// calls is, for each function, the package-level names it calls by bare identifier.
	calls := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil, nil, 0, parseErr
		}
		files++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			called := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, isCall := n.(*ast.CallExpr); isCall {
					if ident, isIdent := call.Fun.(*ast.Ident); isIdent {
						called[ident.Name] = true
					}
				}
				return true
			})
			calls[fn.Name.Name] = called
		}
	}

	for name, called := range calls {
		if called[adminPolicyRefusal] && ceilings[name] == "" {
			unlisted = append(unlisted, name)
		}
	}
	sort.Strings(unlisted)

	applied = make(map[string][]string, len(calls))
	for name := range calls {
		reached := map[string]bool{}
		visited := map[string]bool{name: true}
		pending := []string{name}
		for len(pending) > 0 {
			current := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			for callee := range calls[current] {
				if ceiling := ceilings[callee]; ceiling != "" {
					reached[ceiling] = true
					continue
				}
				if _, local := calls[callee]; local && !visited[callee] {
					visited[callee] = true
					pending = append(pending, callee)
				}
			}
		}
		found := make([]string, 0, len(reached))
		for ceiling := range reached {
			found = append(found, ceiling)
		}
		applied[name] = sortedCeilings(found)
	}
	return applied, unlisted, files, nil
}

// adminCeilingOrder is the order ceilings are named in: grant, target, settings.
var adminCeilingOrder = map[string]int{adminCeilingGrant: 0, adminCeilingTarget: 1, adminCeilingSettings: 2}

// sortedCeilings is ceilings in adminCeilingOrder, each once, never nil.
func sortedCeilings(ceilings []string) []string {
	out := make([]string, 0, len(ceilings))
	for _, ceiling := range ceilings {
		if !slices.Contains(out, ceiling) {
			out = append(out, ceiling)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return adminCeilingOrder[out[i]] < adminCeilingOrder[out[j]] })
	return out
}

// describeCeilings names ceilings in a sentence: "no ceiling", "the target ceiling", "the grant and
// target ceilings".
func describeCeilings(ceilings []string) string {
	switch len(ceilings) {
	case 0:
		return "no ceiling"
	case 1:
		return "the " + ceilings[0] + " ceiling"
	}
	return "the " + strings.Join(ceilings[:len(ceilings)-1], ", ") + " and " + ceilings[len(ceilings)-1] + " ceilings"
}

func TestAdminRoutes_EveryWriteRouteIsClassified(t *testing.T) {
	assertAdminRoutesClassified(t, guard.SourceRoot(t), adminRouteClassification, adminPolicyCeilings)
}

// assertAdminRoutesClassified is the reporting half, taking its tree and tables as parameters and
// failing through a guard.Reporter so a rule test can drive it against a fixture.
func assertAdminRoutesClassified(
	r guard.Reporter, root string, classification map[string]adminRouteClass, ceilings map[string]string,
) {
	r.Helper()

	found, routes, files, err := findAdminRouteClassificationGaps(root, classification, ceilings)
	if err != nil {
		r.Fatalf("reading the admin routes and their handlers under %s: %v", root, err)
	}
	// A routes.go whose registration shape the parse no longer matches reads no route, and a
	// handler directory that moved reads no file; either would otherwise pass.
	if routes == 0 {
		r.Fatalf("read no %s route from %s", adminRouteGroupPrefix, adminRoutesFile)
	}
	if files == 0 {
		r.Fatalf("read no production Go file from %s", adminHandlersDir)
	}

	if len(found) > 0 {
		lines := make([]string, 0, len(found))
		for _, f := range found {
			lines = append(lines, f.route+": "+f.reason)
		}
		r.Errorf("%d admin route(s) the administrative policy does not classify as its code applies it:\n\t%s\n\n"+
			"Only an authserver:manage token creates an administrator, changes one, or changes what reaches "+
			"one, and each handler applies that by calling a ceiling. Every admin write route, and every admin "+
			"read that applies a ceiling, has a row in adminRouteClassification naming the ceilings its handler "+
			"applies, or saying why it needs none. A write route whose handler calls no ceiling lets every "+
			"granular scope reaching it write to administrators (#402).",
			len(found), strings.Join(lines, "\n\t"))
	}
}

// adminRouteFixtureRoutes is a routes.go in the registration shape the real one uses: one route
// whose handler applies the target ceiling, one applying the grant and target ceilings through a
// helper, a create applying none, and a read applying the target ceiling.
const adminRouteFixtureRoutes = `package server

func (s *Server) initRoutes() {
	api.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(apiBearer.JwtAuthorizationHeaderToContext())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}", apihandlers.HandleUserGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/enabled", apihandlers.HandleUserEnabledPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/permissions", apihandlers.HandleUserPermissionsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/users/create", apihandlers.HandleUserCreatePost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Get("/clients/{id}/secret", apihandlers.HandleClientSecretGet(s.database, auditLogger))
	})
	api.Route("/api/v1/account", func(r chi.Router) {
		r.Put("/profile", apihandlers.HandleAccountProfilePut(s.database, auditLogger))
	})
}
`

// adminRouteFixturePolicy is the handler package's policy: the ceilings and the refusal.
const adminRouteFixturePolicy = `package apihandlers

func refuseAdministratorChange(w http.ResponseWriter, r *http.Request) {}

func grantCeilingAllows(w http.ResponseWriter, r *http.Request) bool {
	refuseAdministratorChange(w, r)
	return false
}

func userTargetCeilingAllows(w http.ResponseWriter, r *http.Request) bool {
	refuseAdministratorChange(w, r)
	return false
}

func clientTargetCeilingAllows(w http.ResponseWriter, r *http.Request) bool {
	refuseAdministratorChange(w, r)
	return false
}
`

// adminRouteFixtureHandlers is the handlers the fixture routes name. The permissions save reaches
// the grant ceiling through a helper of its own package, which is a ceiling it applies.
const adminRouteFixtureHandlers = `package apihandlers

func HandleUserGet(database Database) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func HandleUserEnabledPut(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userTargetCeilingAllows(w, r) {
			return
		}
	}
}

func HandleUserPermissionsPut(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !permissionsAllowed(w, r) {
			return
		}
	}
}

func permissionsAllowed(w http.ResponseWriter, r *http.Request) bool {
	return grantCeilingAllows(w, r) && userTargetCeilingAllows(w, r)
}

func HandleUserCreatePost(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func HandleClientSecretGet(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clientTargetCeilingAllows(w, r) {
			return
		}
	}
}

func HandleAccountProfilePut(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}
`

// adminRouteFixtureCeilings is the fixture's adminPolicyCeilings.
var adminRouteFixtureCeilings = map[string]string{
	"grantCeilingAllows":        adminCeilingGrant,
	"userTargetCeilingAllows":   adminCeilingTarget,
	"clientTargetCeilingAllows": adminCeilingTarget,
}

// adminRouteFixtureClassification classifies the fixture exactly as its code applies the policy.
func adminRouteFixtureClassification() map[string]adminRouteClass {
	return map[string]adminRouteClass{
		"PUT /api/v1/admin/users/{id}/enabled":     appliesCeilings(adminCeilingTarget),
		"PUT /api/v1/admin/users/{id}/permissions": appliesCeilings(adminCeilingGrant, adminCeilingTarget),
		"POST /api/v1/admin/users/create":          outsideCeilings("creates a user, who is never an administrator"),
		"GET /api/v1/admin/clients/{id}/secret":    appliesCeilings(adminCeilingTarget),
	}
}

// writeAdminRouteFixture writes the fixture tree under a new root, with handlers as the handler
// file's source, and returns the root.
func writeAdminRouteFixture(t *testing.T, handlers string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range map[string]string{
		adminRoutesFile:                           adminRouteFixtureRoutes,
		adminHandlersDir + "/administrative.go":   adminRouteFixturePolicy,
		adminHandlersDir + "/handlers.go":         handlers,
		adminHandlersDir + "/handlers_test.go":    "package apihandlers\n\nfunc refuseInATest() { refuseAdministratorChange(nil, nil) }\n",
		"authserver/internal/handlers/handler.go": "package handlers\n\nfunc HandleUserGet() {}\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(src), 0o600))
	}
	return root
}

// runAdminRouteGuard drives the reporting half over a fixture root.
func runAdminRouteGuard(root string, classification map[string]adminRouteClass, ceilings map[string]string) guard.Report {
	return guard.Run(func(r guard.Reporter) {
		assertAdminRoutesClassified(r, root, classification, ceilings)
	})
}

func TestAdminRouteClassification_Guard_PassesATreeItClassifies(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)

	report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

	assert.False(t, report.Stopped, "a tree read in full must not be fatal: %s", report.Fatal)
	assert.Empty(t, report.Errors, "a tree classified as its code applies the policy must pass")
}

func TestAdminRouteClassification_Guard_FailsOnAnUnclassifiedWriteRoute(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
	classification := adminRouteFixtureClassification()
	delete(classification, "POST /api/v1/admin/users/create")
	delete(classification, "PUT /api/v1/admin/users/{id}/enabled")

	report := runAdminRouteGuard(root, classification, adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "2 admin route(s)")
	assert.Contains(t, report.Errors[0], "POST /api/v1/admin/users/create: a write route the policy does not classify; its handler applies no ceiling")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: a write route the policy does not classify; its handler applies the target ceiling")
}

func TestAdminRouteClassification_Guard_FailsOnAnUnclassifiedReadApplyingACeiling(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
	classification := adminRouteFixtureClassification()
	delete(classification, "GET /api/v1/admin/clients/{id}/secret")

	report := runAdminRouteGuard(root, classification, adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "1 admin route(s)")
	assert.Contains(t, report.Errors[0], "GET /api/v1/admin/clients/{id}/secret: a route applying the target ceiling the policy does not classify")
	// A read applying no ceiling needs no row, and the account API is not the admin API.
	assert.NotContains(t, report.Errors[0], "GET /api/v1/admin/users/{id}:")
	assert.NotContains(t, report.Errors[0], "/api/v1/account/")
}

func TestAdminRouteClassification_Guard_FailsOnAWriteRouteWhoseHandlerAppliesNoCeilingItsRowNames(t *testing.T) {
	// The handler that was guarded calls no ceiling any more: the row still says target.
	handlers := strings.Replace(adminRouteFixtureHandlers,
		"\t\tif !userTargetCeilingAllows(w, r) {\n\t\t\treturn\n\t\t}\n\t}\n}\n\nfunc HandleUserPermissionsPut",
		"\t}\n}\n\nfunc HandleUserPermissionsPut", 1)
	require.NotEqual(t, adminRouteFixtureHandlers, handlers, "the fixture edit must apply")
	root := writeAdminRouteFixture(t, handlers)

	report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "1 admin route(s)")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: classified as applying the target ceiling, but its handler applies no ceiling")
}

func TestAdminRouteClassification_Guard_FailsOnARowNamingOtherCeilingsThanTheHandlerApplies(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
	classification := adminRouteFixtureClassification()
	classification["PUT /api/v1/admin/users/{id}/permissions"] = appliesCeilings(adminCeilingTarget)
	classification["POST /api/v1/admin/users/create"] = appliesCeilings(adminCeilingTarget)
	classification["PUT /api/v1/admin/users/{id}/enabled"] = outsideCeilings("a toggle")

	report := runAdminRouteGuard(root, classification, adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "3 admin route(s)")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/permissions: classified as applying the target ceiling, but its handler applies the grant and target ceilings")
	assert.Contains(t, report.Errors[0], "POST /api/v1/admin/users/create: classified as applying the target ceiling, but its handler applies no ceiling")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: classified as outside the ceilings, but its handler applies the target ceiling")
}

func TestAdminRouteClassification_Guard_FailsOnAStaleRow(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
	classification := adminRouteFixtureClassification()
	classification["DELETE /api/v1/admin/users/{id}"] = appliesCeilings(adminCeilingTarget)
	classification["PUT /api/v1/account/profile"] = outsideCeilings("the caller's own profile")

	report := runAdminRouteGuard(root, classification, adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "2 admin route(s)")
	assert.Contains(t, report.Errors[0], "DELETE /api/v1/admin/users/{id}: classified, but routes.go registers no such admin route")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/account/profile: classified, but routes.go registers no such admin route")
}

func TestAdminRouteClassification_Guard_FailsOnAMalformedRow(t *testing.T) {
	root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
	classification := adminRouteFixtureClassification()
	classification["POST /api/v1/admin/users/create"] = adminRouteClass{}
	classification["PUT /api/v1/admin/users/{id}/enabled"] = adminRouteClass{ceilings: []string{adminCeilingTarget}, outside: "and a reason"}
	classification["PUT /api/v1/admin/users/{id}/permissions"] = appliesCeilings(adminCeilingGrant, "everything")

	report := runAdminRouteGuard(root, classification, adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "3 admin route(s)")
	assert.Contains(t, report.Errors[0], "POST /api/v1/admin/users/create: a row names its ceilings or why it needs none, and this names neither")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: a row names its ceilings or why it needs none, and this names both")
	assert.Contains(t, report.Errors[0], `PUT /api/v1/admin/users/{id}/permissions: names "everything", which is no ceiling`)
}

func TestAdminRouteClassification_Guard_FailsOnAnUnlistedCeiling(t *testing.T) {
	// A new ceiling a handler calls, which the guard does not know: the handler would otherwise
	// read as applying none, and a row saying so would pass.
	handlers := adminRouteFixtureHandlers + `
func secretCeilingAllows(w http.ResponseWriter, r *http.Request) bool {
	refuseAdministratorChange(w, r)
	return false
}
`
	root := writeAdminRouteFixture(t, handlers)

	report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "1 admin route(s)")
	assert.Contains(t, report.Errors[0], "secretCeilingAllows: answers a refusal through refuseAdministratorChange, but adminPolicyCeilings does not list it as a ceiling")
}

func TestAdminRouteClassification_Guard_FailsOnAHandlerTheWalkCannotRead(t *testing.T) {
	root := writeAdminRouteFixture(t, strings.Replace(adminRouteFixtureHandlers,
		"func HandleUserCreatePost(", "func handleUserCreatePost(", 1))

	report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "1 admin route(s)")
	assert.Contains(t, report.Errors[0], "POST /api/v1/admin/users/create: its handler apihandlers.HandleUserCreatePost is not a function apihandlers declares, so what it applies cannot be read")
}

func TestAdminRouteClassification_Guard_IsFatalOnAnEmptyRead(t *testing.T) {
	t.Run("no admin route", func(t *testing.T) {
		root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
		p := filepath.Join(root, filepath.FromSlash(adminRoutesFile))
		require.NoError(t, os.WriteFile(p, []byte("package server\n\nfunc (s *Server) initRoutes() {}\n"), 0o600))

		report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

		require.True(t, report.Stopped, "a routes.go with no admin route must be fatal rather than a pass")
		assert.Contains(t, report.Fatal, "read no /api/v1/admin route from "+adminRoutesFile)
	})

	t.Run("no handler file", func(t *testing.T) {
		root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
		dir := filepath.Join(root, filepath.FromSlash(adminHandlersDir))
		require.NoError(t, os.Remove(filepath.Join(dir, "administrative.go")))
		require.NoError(t, os.Remove(filepath.Join(dir, "handlers.go")))

		report := runAdminRouteGuard(root, map[string]adminRouteClass{}, adminRouteFixtureCeilings)

		require.True(t, report.Stopped, "a handler directory with no production file must be fatal rather than a pass")
		assert.Contains(t, report.Fatal, "read no production Go file from "+adminHandlersDir)
	})

	t.Run("no routes.go", func(t *testing.T) {
		root := writeAdminRouteFixture(t, adminRouteFixtureHandlers)
		require.NoError(t, os.Remove(filepath.Join(root, filepath.FromSlash(adminRoutesFile))))

		report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

		require.True(t, report.Stopped, "a missing routes.go must be fatal rather than a pass")
		assert.Contains(t, report.Fatal, "reading the admin routes and their handlers")
	})
}
