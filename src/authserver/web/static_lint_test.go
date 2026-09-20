package web

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

// This file holds what no tier of this repository can otherwise observe. There is no JavaScript
// test runner here and the auth server has no render test package, so the only thing that can see
// what its pages ship to a browser is the embedded FS itself. Both guards read through staticFS and
// templateFS rather than off disk, for the reason adminconsole/web/static_lint_test.go gives: those
// are the byte streams StaticFS() and TemplateFS() hand the router, so a file that stopped being
// embedded fails here rather than passing a lint and then 404ing in production.
//
// Both are lexical, and neither pretends otherwise. A call reached by some spelling other than
// `name(`, or a layout assembled at runtime, is out of reach, and closing that would mean parsing
// two languages this module does not depend on.

// servedFiles returns every embedded file under dir whose name ends in ext, keyed by its path.
func servedFiles(t *testing.T, fsys fs.FS, dir, ext string) map[string]string {
	t.Helper()

	out := map[string]string{}
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ext) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for %s files: %v", dir, ext, err)
	}
	return out
}

// jsDeclRe matches a top-level declaration in a served script, in either of the two forms this
// file uses: `function name(` and `const name = (`. Both start in column zero, which is what
// keeps a nested helper out of the set: a function declared inside another is not something a
// template can call, so it is part of its parent's body rather than a declaration of its own.
var jsDeclRe = regexp.MustCompile(`(?m)^(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)`)

// callRe matches a call to name that is not a property access, so `props.t(` and a comment's
// `t()` are treated alike: a bare identifier followed by an open parenthesis.
func callRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_.$])` + regexp.QuoteMeta(name) + `\s*\(`)
}

type jsDecl struct {
	name string
	body string
}

// jsDecls splits a served script into its top-level declarations. A declaration's body runs to the
// start of the next one, which needs no brace matching and is exact for a file written this way.
func jsDecls(src string) []jsDecl {
	locs := jsDeclRe.FindAllStringSubmatchIndex(src, -1)
	decls := make([]jsDecl, 0, len(locs))
	for i, loc := range locs {
		name := ""
		for _, g := range [][2]int{{2, 3}, {4, 5}} {
			if loc[g[0]] >= 0 {
				name = src[loc[g[0]]:loc[g[1]]]
			}
		}
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		decls = append(decls, jsDecl{name: name, body: src[loc[0]:end]})
	}
	return decls
}

// TestUtilsJS_EveryFunctionIsReachedFromATemplate holds the served static scripts to carrying only
// what the served templates can actually reach.
//
// It checks reachability rather than a list of names that must be absent, because a denylist cannot
// see the defect #226 was filed about. Before #360 this file declared seven functions, of which one
// was called by two templates; `t` and `tFormat` were called, but only from inside sendAjaxRequest,
// which nothing called. Every name was referenced somewhere and six of the seven were dead. So the
// roots here are the calls a template makes, and the set grows only through the bodies of functions
// already reachable.
//
// It is also why this is not spelled as "utils.js must define showModalDialog and nothing else":
// TestLayouts_JSBootstrapHasAReader below promises that a future page needing client-side strings
// may add `t` back, and a denylist would refuse it. Reachability admits it the moment a template
// calls it, and refuses it until then.
func TestUtilsJS_EveryFunctionIsReachedFromATemplate(t *testing.T) {
	scripts := servedFiles(t, staticFS, "static", ".js")
	templates := servedFiles(t, templateFS, "template", ".html")

	if len(scripts) == 0 || len(templates) == 0 {
		t.Fatalf("found %d served scripts and %d served templates; the //go:embed set stopped "+
			"matching, so this guard read nothing", len(scripts), len(templates))
	}

	for file, src := range scripts {
		decls := jsDecls(src)
		if len(decls) == 0 {
			t.Errorf("%s: no top-level declaration parsed. Either the file is written in a shape "+
				"jsDeclRe cannot see, in which case teach it, or it is empty and should not be "+
				"served", file)
			continue
		}

		// Roots: a name called from a template, or from a different served script. Calls inside
		// the declaring file are not roots -- that is the whole point, and the transitive pass
		// below is what carries them.
		reached := map[string]bool{}
		for _, d := range decls {
			re := callRe(d.name)
			for _, tpl := range templates {
				if re.MatchString(tpl) {
					reached[d.name] = true
					break
				}
			}
			for other, otherSrc := range scripts {
				if other != file && re.MatchString(otherSrc) {
					reached[d.name] = true
					break
				}
			}
		}

		// Expand through the bodies of the functions already reachable, until nothing new
		// arrives. Bounded by the declaration count: each pass either adds a name or stops.
		for changed := true; changed; {
			changed = false
			for _, from := range decls {
				if !reached[from.name] {
					continue
				}
				for _, to := range decls {
					if reached[to.name] || to.name == from.name {
						continue
					}
					if callRe(to.name).MatchString(from.body) {
						reached[to.name] = true
						changed = true
					}
				}
			}
		}

		for _, d := range decls {
			if !reached[d.name] {
				t.Errorf("%s: %s() is declared but no served template reaches it, directly or "+
					"through another function a template calls. Dead client-side code is served "+
					"to every visitor and read by the next maintainer as live; delete it, or call "+
					"it from the page that needs it (#360)", file, d.name)
			}
		}

		// The file this guard was written for. Without this, deleting showModalDialog and its two
		// callers together would leave an empty file passing every assertion above.
		if file == "static/utils.js" && !reached["showModalDialog"] {
			t.Errorf("static/utils.js: showModalDialog is gone, and it is what forgot_password.html " +
				"and reset_password.html call. If that is deliberate, this guard needs a new " +
				"anchor rather than deletion")
		}
	}
}

// TestLayouts_JSBootstrapHasAReader states the coherence rule the JSBootstrap chain needs, as an
// implication in both directions, so that either half alone fails and both halves together pass.
//
// The chain is: a layout emits {{ JSBootstrap }}, which renders <script>window.i18n={...}</script>,
// and a served script reads window.i18n to resolve a key. Half of it is useless and neither half
// fails loudly on its own. The block without a reader is what the auth server shipped until #360 --
// nineteen localized strings on every page, eleven of them for an image-upload script this server
// does not serve, and nothing anywhere to read them. A reader without the block is the mirror: every
// lookup falls back to returning its own key, so the browser shows "js.error.error_title" to the
// user, which is the failure TestRender_JSBootstrapNoKeyLeak catches for the admin console from the
// rendered side.
//
// Stated this way the rule does not forbid client-side strings in the auth server; it requires that
// adding them means adding both halves.
func TestLayouts_JSBootstrapHasAReader(t *testing.T) {
	scripts := servedFiles(t, staticFS, "static", ".js")
	templates := servedFiles(t, templateFS, "template", ".html")

	if len(scripts) == 0 || len(templates) == 0 {
		t.Fatalf("found %d served scripts and %d served templates; the //go:embed set stopped "+
			"matching, so this guard read nothing", len(scripts), len(templates))
	}

	var emitters []string
	for file, src := range templates {
		if strings.Contains(src, "JSBootstrap") {
			emitters = append(emitters, file)
		}
	}

	var readers []string
	for file, src := range scripts {
		if strings.Contains(src, "window.i18n") {
			readers = append(readers, file)
		}
	}

	switch {
	case len(emitters) > 0 && len(readers) == 0:
		t.Errorf("%s calls JSBootstrap, which emits window.i18n, but no served script reads it. "+
			"Every page then ships a <script> block of localized strings nothing consumes. Serve a "+
			"reader, or drop the call (#360)", path.Base(emitters[0]))
	case len(readers) > 0 && len(emitters) == 0:
		t.Errorf("%s reads window.i18n but no served template calls JSBootstrap, so the table is "+
			"never populated and every lookup falls back to returning its own key: the visitor is "+
			"shown a catalog key where a sentence belongs. Add {{ JSBootstrap $.ctx }} to the "+
			"layouts that serve this script (#360)", path.Base(readers[0]))
	}
}
