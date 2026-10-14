package authflow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
)

func TestParkedAuthorizeForm(t *testing.T) {
	t.Run("keeps every copy of each listed parameter, in order", func(t *testing.T) {
		params := url.Values{"state": {"a", "b"}, "scope": {"openid"}, "prompt": {"login", "consent"}}
		assert.Equal(t, params, parkedAuthorizeForm(params))
	})

	t.Run("drops what nothing reads, and request_handle", func(t *testing.T) {
		form := parkedAuthorizeForm(url.Values{
			"client_id": {"c"}, "login_hint": {"x"}, "junk": {"y"}, authorizerequest.HandleParameter: {"z"},
		})
		assert.Equal(t, url.Values{"client_id": {"c"}}, form)
	})

	t.Run("keeps a listed parameter that was sent empty", func(t *testing.T) {
		assert.Equal(t, url.Values{"state": {""}}, parkedAuthorizeForm(url.Values{"state": {""}}),
			"an empty state is a value the ceremony reads, and a difference the GET must see")
	})

	t.Run("owns its slices", func(t *testing.T) {
		params := url.Values{"state": {"a"}}
		form := parkedAuthorizeForm(params)
		params["state"][0] = "changed"
		assert.Equal(t, "a", form.Get("state"))
	})
}

// The list of what is parked is held to authorization.go's reads, so a parameter read later cannot
// be left out and silently vanish between a POST and its GET. It is the parameters the endpoint reads
// (TestAuthorizeRequestParameters_EveryReadIsListed owns that list) and the two it reads only to
// refuse, and not the handle.
func TestAuthorizeParkedParameters_CoverEveryRead(t *testing.T) {
	isParams := func(e ast.Expr) bool {
		ident, ok := e.(*ast.Ident)
		return ok && ident.Name == "params"
	}
	reads := formReads(t, "authorization.go", isParams)

	parsed, err := parser.ParseFile(token.NewFileSet(), "authorization.go", nil, 0)
	require.NoError(t, err)
	var presence []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Has" || !isParams(sel.X) || len(call.Args) != 1 {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			name, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			presence = append(presence, name)
		}
		return true
	})
	require.ElementsMatch(t, []string{"request", "request_uri"}, presence,
		"the two parameters authorization.go reads only for their presence")

	for _, name := range append(slices.Clone(reads), presence...) {
		assert.Contains(t, authorizeParkedParameters, name, "authorization.go reads %q", name)
	}
	assert.ElementsMatch(t, append(slices.Clone(authorizeRequestParameters), "request", "request_uri"), authorizeParkedParameters)
	assert.NotContains(t, authorizeParkedParameters, authorizerequest.HandleParameter)
}
