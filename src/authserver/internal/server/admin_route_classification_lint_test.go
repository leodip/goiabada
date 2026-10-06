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
	"grantCeilingAllows":                 adminCeilingGrant,
	"membershipCeilingAllows":            adminCeilingGrant,
	"userGroupsCeilingAllows":            adminCeilingGrant,
	"groupDeletionCeilingAllows":         adminCeilingGrant,
	"userTargetCeilingAllows":            adminCeilingTarget,
	"groupTargetCeilingAllows":           adminCeilingTarget,
	"clientTargetCeilingAllows":          adminCeilingTarget,
	"allowanceCeilingAllows":             adminCeilingTarget,
	"permissionDescriptionCeilingAllows": adminCeilingTarget,
	"settingsCeilingAllows":              adminCeilingSettings,
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
	// Switching a client's allowance to request the administrative scopes makes an administrator
	// client or changes one, so every caller below authserver:manage is refused it (#499 decision 4).
	"PUT /api/v1/admin/clients/{id}/administrative-scopes": appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/clients/{id}":                    appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/clients/{id}/logo":                 appliesCeilings(adminCeilingTarget),
	"DELETE /api/v1/admin/clients/{id}/logo":               appliesCeilings(adminCeilingTarget),
	"POST /api/v1/admin/clients": outsideCeilings("creates a client, which holds no permission: a new client is " +
		"never an administrator"),

	// Resources and their permissions.
	"POST /api/v1/admin/resources": outsideCeilings("creates a resource, whose permissions confer no power in " +
		"this server"),
	"PUT /api/v1/admin/resources/{id}": outsideCeilings("the authserver resource's identifier cannot be changed, " +
		"and no other resource's permissions confer power in this server"),
	"DELETE /api/v1/admin/resources/{id}": outsideCeilings("the authserver resource cannot be deleted, and no " +
		"other resource's permissions confer power in this server"),
	"PUT /api/v1/admin/resources/{resourceId}/permissions": appliesCeilings(adminCeilingTarget),

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
	// route is METHOD pattern, or the function's name for an unlisted ceiling or a ceiling it
	// does not refuse on or applies after a write.
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

	applied, unlisted, misapplied, files, err := adminHandlerCeilings(filepath.Join(root, filepath.FromSlash(adminHandlersDir)), ceilings)
	if err != nil {
		return nil, 0, 0, err
	}
	for _, name := range unlisted {
		found = append(found, adminRouteFinding{route: name, reason: "answers a refusal through " + adminPolicyRefusal +
			", but adminPolicyCeilings does not list it as a ceiling"})
	}
	found = append(found, misapplied...)

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
// every package-level function it declares, the ceilings it applies, sorted and each once. A
// function applies a ceiling only by refusing on its answer, in one of two shapes: the call is the
// whole condition of `if !ceiling(...) { ...; return }`, or its last result is assigned to a
// variable that the very next statement refuses on, `if !allowed { ...; return }`. A call in any
// other place, its answer ignored, discarded or merely stored, applies nothing, so the row naming
// that ceiling fails. A function of the package whose one result is a bool passes the ceilings it
// returns, `return grantCeilingAllows(...) && userTargetCeilingAllows(...)`, to every caller
// refusing on it in the same two shapes. A call to a ceiling counts as that ceiling and is not
// followed further.
//
// It also returns, sorted, every function calling the refusal that ceilings does not list, every
// call to a ceiling or to a function returning one that refuses on nothing, and every ceiling
// applied after a write that runs before it; and how many files it read. A write is a call through
// a parameter whose type is named ...Database, its method not a Get, or a call handing that
// parameter to anything but a ceiling: the handlers read their target before deciding, so a
// refusal answers 404 first, and write nothing before it. A write runs before a ceiling when it is
// earlier in the source and not in a block that ends in a return without holding the ceiling, so
// a branch that refuses, writes and answers does not count against the next branch's ceiling. A
// ceiling missing from one branch of a handler is beyond this walk, and stays the per-route tests'
// to catch.
func adminHandlerCeilings(dir string, ceilings map[string]string) (
	applied map[string][]string, unlisted []string, misapplied []adminRouteFinding, files int, err error,
) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	var functions []*ast.FuncDecl
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil, nil, nil, 0, parseErr
		}
		files++
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
				functions = append(functions, fn)
			}
		}
	}

	// calls is, for each function, the package-level names it calls by bare identifier; gates, the
	// calls it refuses on, by name and position; passes, the names a bool function returns.
	calls := map[string]map[string]bool{}
	gates := map[string][]adminGate{}
	passes := map[string]map[string]bool{}
	for _, fn := range functions {
		calls[fn.Name.Name] = map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, isCall := n.(*ast.CallExpr); isCall {
				if ident, isIdent := call.Fun.(*ast.Ident); isIdent {
					calls[fn.Name.Name][ident.Name] = true
				}
			}
			return true
		})
		gates[fn.Name.Name] = adminGatesIn(fn.Body)
		passes[fn.Name.Name] = adminPassedCalls(fn)
	}

	for name, called := range calls {
		if called[adminPolicyRefusal] && ceilings[name] == "" {
			unlisted = append(unlisted, name)
		}
	}
	sort.Strings(unlisted)

	// reach is the ceilings a call to name applies when refused on: a ceiling itself, or what a
	// function of the package refuses on and returns.
	var reach func(name string, visited map[string]bool) map[string]bool
	reach = func(name string, visited map[string]bool) map[string]bool {
		if ceiling := ceilings[name]; ceiling != "" {
			return map[string]bool{ceiling: true}
		}
		reached := map[string]bool{}
		if visited[name] {
			return reached
		}
		visited[name] = true
		for _, gate := range gates[name] {
			for ceiling := range reach(gate.callee, visited) {
				reached[ceiling] = true
			}
		}
		for callee := range passes[name] {
			for ceiling := range reach(callee, visited) {
				reached[ceiling] = true
			}
		}
		return reached
	}

	applied = make(map[string][]string, len(calls))
	for name := range calls {
		found := make([]string, 0)
		for ceiling := range reach(name, map[string]bool{}) {
			found = append(found, ceiling)
		}
		applied[name] = sortedCeilings(found)
	}

	// A call that applies a ceiling when refused on, and is not, is reported where it sits. The
	// ceilings' own bodies are the policy and are not held to it.
	for _, fn := range functions {
		name := fn.Name.Name
		if ceilings[name] != "" {
			continue
		}
		gated := map[token.Pos]bool{}
		for _, gate := range gates[name] {
			gated[gate.pos] = true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			ident, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || gated[call.Pos()] || passes[name][ident.Name] ||
				len(reach(ident.Name, map[string]bool{name: true})) == 0 {
				return true
			}
			misapplied = append(misapplied, adminRouteFinding{route: name, reason: "calls " + ident.Name +
				" without refusing on its answer: a ceiling applies only as `if !" + ident.Name +
				"(...) { return }`, or assigned to a variable the next statement refuses on"})
			return true
		})

		writes := adminWrites(fn, ceilings)
		returning := adminReturningBlocks(fn.Body)
		for _, gate := range gates[name] {
			if len(reach(gate.callee, map[string]bool{name: true})) == 0 {
				continue
			}
			if write := adminWriteReaching(writes, returning, gate.pos); write != "" {
				misapplied = append(misapplied, adminRouteFinding{route: name, reason: "applies " + gate.callee +
					" after its write " + write + ", so a refusal would answer a request that already wrote"})
			}
		}
	}
	sort.SliceStable(misapplied, func(i, j int) bool { return misapplied[i].route < misapplied[j].route })
	return applied, unlisted, misapplied, files, nil
}

// adminGate is a call a function refuses on: the name it calls and where the call is.
type adminGate struct {
	callee string
	pos    token.Pos
}

// adminGatesIn is every call in body refused on in one of the two shapes adminHandlerCeilings
// accepts, closures included.
func adminGatesIn(body *ast.BlockStmt) []adminGate {
	var gates []adminGate
	ast.Inspect(body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch block := n.(type) {
		case *ast.BlockStmt:
			list = block.List
		case *ast.CaseClause:
			list = block.Body
		case *ast.CommClause:
			list = block.Body
		default:
			return true
		}
		for i, stmt := range list {
			// if !ceiling(...) { ...; return }
			if refusal, isIf := stmt.(*ast.IfStmt); isIf {
				if call := adminRefusedCall(refusal); call != nil {
					gates = append(gates, adminGate{callee: call.Fun.(*ast.Ident).Name, pos: call.Pos()})
				}
				continue
			}
			// _, allowed := ceiling(...) followed by if !allowed { ...; return }
			assign, isAssign := stmt.(*ast.AssignStmt)
			if !isAssign || len(assign.Rhs) != 1 || i+1 == len(list) {
				continue
			}
			call, isCall := assign.Rhs[0].(*ast.CallExpr)
			if !isCall {
				continue
			}
			callee, isIdent := call.Fun.(*ast.Ident)
			result, isVariable := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
			if !isIdent || !isVariable || result.Name == "_" {
				continue
			}
			next, isIf := list[i+1].(*ast.IfStmt)
			if !isIf {
				continue
			}
			if refused := adminRefusedIdent(next); refused != nil && refused.Name == result.Name {
				gates = append(gates, adminGate{callee: callee.Name, pos: call.Pos()})
			}
		}
		return true
	})
	return gates
}

// adminRefusal is the negated condition of an if statement that has no init and no else and whose
// body ends in a return, or nil for any other if statement.
func adminRefusal(stmt *ast.IfStmt) ast.Expr {
	if stmt.Init != nil || stmt.Else != nil || len(stmt.Body.List) == 0 {
		return nil
	}
	if _, returns := stmt.Body.List[len(stmt.Body.List)-1].(*ast.ReturnStmt); !returns {
		return nil
	}
	not, isNot := stmt.Cond.(*ast.UnaryExpr)
	if !isNot || not.Op != token.NOT {
		return nil
	}
	return ast.Unparen(not.X)
}

// adminRefusedCall is the call to a package-level function an if statement refuses on, or nil.
func adminRefusedCall(stmt *ast.IfStmt) *ast.CallExpr {
	call, isCall := adminRefusal(stmt).(*ast.CallExpr)
	if !isCall {
		return nil
	}
	if _, isIdent := call.Fun.(*ast.Ident); !isIdent {
		return nil
	}
	return call
}

// adminRefusedIdent is the variable an if statement refuses on, or nil.
func adminRefusedIdent(stmt *ast.IfStmt) *ast.Ident {
	ident, _ := adminRefusal(stmt).(*ast.Ident)
	return ident
}

// adminPassedCalls is, for a function whose one result is a bool, the package-level functions its
// return statements call as operands of &&, whose refusal is therefore the function's own.
func adminPassedCalls(fn *ast.FuncDecl) map[string]bool {
	passed := map[string]bool{}
	results := fn.Type.Results
	if results == nil || len(results.List) != 1 || len(results.List[0].Names) > 1 {
		return passed
	}
	if result, isIdent := results.List[0].Type.(*ast.Ident); !isIdent || result.Name != "bool" {
		return passed
	}
	var operands func(expr ast.Expr)
	operands = func(expr ast.Expr) {
		switch e := ast.Unparen(expr).(type) {
		case *ast.BinaryExpr:
			if e.Op == token.LAND {
				operands(e.X)
				operands(e.Y)
			}
		case *ast.CallExpr:
			if ident, isIdent := e.Fun.(*ast.Ident); isIdent {
				passed[ident.Name] = true
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isClosure := n.(*ast.FuncLit); isClosure {
			return false
		}
		if ret, isReturn := n.(*ast.ReturnStmt); isReturn && len(ret.Results) == 1 {
			operands(ret.Results[0])
		}
		return true
	})
	return passed
}

// adminWrite is a write a function makes through a database port, spelled as written, and where.
type adminWrite struct {
	call string
	pos  token.Pos
}

// adminWrites is every write fn makes through a database port parameter, in source order.
func adminWrites(fn *ast.FuncDecl, ceilings map[string]string) []adminWrite {
	ports := map[string]bool{}
	for _, field := range fn.Type.Params.List {
		var typeName string
		switch t := field.Type.(type) {
		case *ast.Ident:
			typeName = t.Name
		case *ast.SelectorExpr:
			typeName = t.Sel.Name
		}
		if strings.HasSuffix(strings.ToLower(typeName), "database") {
			for _, name := range field.Names {
				ports[name.Name] = true
			}
		}
	}
	if len(ports) == 0 {
		return nil
	}

	var writes []adminWrite
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector {
			if port, isIdent := selector.X.(*ast.Ident); isIdent && ports[port.Name] {
				if !strings.HasPrefix(selector.Sel.Name, "Get") {
					writes = append(writes, adminWrite{call: port.Name + "." + selector.Sel.Name, pos: call.Pos()})
				}
				return true
			}
		}
		if callee, isIdent := call.Fun.(*ast.Ident); isIdent && ceilings[callee.Name] != "" {
			return true
		}
		for _, arg := range call.Args {
			if port, isIdent := arg.(*ast.Ident); isIdent && ports[port.Name] {
				writes = append(writes, adminWrite{call: adminCallName(call.Fun) + "(..., " + port.Name + ", ...)", pos: call.Pos()})
				break
			}
		}
		return true
	})
	return writes
}

// adminReturningBlocks is every block in body whose last statement is a return: what runs in one
// ends the function there, so a write in it never precedes anything after the block.
func adminReturningBlocks(body *ast.BlockStmt) []*ast.BlockStmt {
	var blocks []*ast.BlockStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if block, isBlock := n.(*ast.BlockStmt); isBlock && len(block.List) > 0 {
			if _, returns := block.List[len(block.List)-1].(*ast.ReturnStmt); returns {
				blocks = append(blocks, block)
			}
		}
		return true
	})
	return blocks
}

// adminWriteReaching is the first write that runs before a ceiling at pos can: one earlier in the
// source and not inside a block ending in a return that does not also hold the ceiling, as a
// branch that writes and answers is. Empty when there is none.
func adminWriteReaching(writes []adminWrite, returning []*ast.BlockStmt, pos token.Pos) string {
	for _, write := range writes {
		if write.pos >= pos {
			break
		}
		ended := false
		for _, block := range returning {
			holdsWrite := block.Pos() <= write.pos && write.pos < block.End()
			holdsCeiling := block.Pos() <= pos && pos < block.End()
			if holdsWrite && !holdsCeiling {
				ended = true
				break
			}
		}
		if !ended {
			return write.call
		}
	}
	return ""
}

// adminCallName spells the function a call names, for a finding.
func adminCallName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return adminCallName(f.X) + "." + f.Sel.Name
	}
	return "a call"
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

// adminRouteFixtureHandlers is the handlers the fixture routes name, each refusing on its ceilings
// before it writes, in every shape the guard accepts. The permissions save reaches the grant
// ceiling through a helper of its own package returning it, which is a ceiling it applies, and
// gates each of two branches before the write in that branch; the secret read refuses on a
// variable its ceiling's answer was assigned to.
const adminRouteFixtureHandlers = `package apihandlers

func HandleUserGet(database Database) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func HandleUserEnabledPut(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := database.GetUserById(r)
		if !userTargetCeilingAllows(w, r) {
			return
		}
		database.UpdateUserEnabled(user)
	}
}

func HandleUserPermissionsPut(database Database, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength == 0 {
			if !permissionsAllowed(w, r) {
				return
			}
			database.DeleteUserPermissions(r)
			return
		}
		if !permissionsAllowed(w, r) {
			return
		}
		database.SaveUserPermissions(r)
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
		allowed := clientTargetCeilingAllows(w, r)
		if !allowed {
			auditLogger.Log(r)
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
		"\t\tif !userTargetCeilingAllows(w, r) {\n\t\t\treturn\n\t\t}\n\t\tdatabase.UpdateUserEnabled(user)\n",
		"\t\tdatabase.UpdateUserEnabled(user)\n", 1)
	require.NotEqual(t, adminRouteFixtureHandlers, handlers, "the fixture edit must apply")
	root := writeAdminRouteFixture(t, handlers)

	report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "1 admin route(s)")
	assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: classified as applying the target ceiling, but its handler applies no ceiling")
}

// The enabled toggle's gate, as the fixture writes it, for the cases below to replace.
const adminRouteFixtureEnabledGate = "\t\tif !userTargetCeilingAllows(w, r) {\n\t\t\treturn\n\t\t}\n" +
	"\t\tdatabase.UpdateUserEnabled(user)\n"

func TestAdminRouteClassification_Guard_FailsOnACeilingWhoseAnswerIsNotRefusedOn(t *testing.T) {
	// A ceiling called and then not refused on answers the refusal and lets the write go on: it
	// applies nothing, whatever the call's shape.
	for name, gate := range map[string]string{
		"its result ignored":   "\t\tuserTargetCeilingAllows(w, r)\n",
		"its result discarded": "\t\t_ = userTargetCeilingAllows(w, r)\n",
		"its result stored":    "\t\tallowed := userTargetCeilingAllows(w, r)\n\t\tlogAllowed(allowed)\n",
		"refused on without returning": "\t\tif !userTargetCeilingAllows(w, r) {\n" +
			"\t\t\tauditLogger.Log(r)\n\t\t}\n",
		"refused on a statement later": "\t\tallowed := userTargetCeilingAllows(w, r)\n\t\tlogAllowed(allowed)\n" +
			"\t\tif !allowed {\n\t\t\treturn\n\t\t}\n",
	} {
		t.Run(name, func(t *testing.T) {
			handlers := strings.Replace(adminRouteFixtureHandlers, adminRouteFixtureEnabledGate,
				gate+"\t\tdatabase.UpdateUserEnabled(user)\n", 1)
			require.NotEqual(t, adminRouteFixtureHandlers, handlers, "the fixture edit must apply")
			root := writeAdminRouteFixture(t, handlers)

			report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

			require.Len(t, report.Errors, 1)
			assert.Contains(t, report.Errors[0], "2 admin route(s)")
			assert.Contains(t, report.Errors[0], "HandleUserEnabledPut: calls userTargetCeilingAllows without refusing on its answer")
			assert.Contains(t, report.Errors[0], "PUT /api/v1/admin/users/{id}/enabled: classified as applying the target ceiling, but its handler applies no ceiling")
		})
	}
}

func TestAdminRouteClassification_Guard_FailsOnACeilingAppliedAfterAWrite(t *testing.T) {
	// A refusal after the write answers a request that already changed the administrator.
	for name, tc := range map[string]struct{ write, finding string }{
		"through the port": {
			write:   "\t\tdatabase.UpdateUserEnabled(user)\n",
			finding: "HandleUserEnabledPut: applies userTargetCeilingAllows after its write database.UpdateUserEnabled",
		},
		"handing the port on": {
			write:   "\t\trevocation.RevokeUser(r.Context(), database, user)\n",
			finding: "HandleUserEnabledPut: applies userTargetCeilingAllows after its write revocation.RevokeUser(..., database, ...)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			handlers := strings.Replace(adminRouteFixtureHandlers, adminRouteFixtureEnabledGate,
				tc.write+"\t\tif !userTargetCeilingAllows(w, r) {\n\t\t\treturn\n\t\t}\n", 1)
			require.NotEqual(t, adminRouteFixtureHandlers, handlers, "the fixture edit must apply")
			root := writeAdminRouteFixture(t, handlers)

			report := runAdminRouteGuard(root, adminRouteFixtureClassification(), adminRouteFixtureCeilings)

			require.Len(t, report.Errors, 1)
			assert.Contains(t, report.Errors[0], "1 admin route(s)")
			assert.Contains(t, report.Errors[0], tc.finding+", so a refusal would answer a request that already wrote")
		})
	}
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
