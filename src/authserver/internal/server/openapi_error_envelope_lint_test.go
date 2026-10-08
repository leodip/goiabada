package server

// openapi.yaml's error envelope, held to what the auth server's writers send (#522 decision 3).
//
// The ErrorResponse schema is what a client generated from the spec expects in every admin and
// account API refusal. TestOpenAPI_SchemaPropertiesMatchTheAPIStructs holds it to api.ErrorResponse's
// JSON tags, which is not the same thing: the envelope declared error_args for as long as the struct
// carried an omitempty map for it, and no writer ever set the map, so the field was promised to
// every caller and arrived for none. This reads which fields the writers really send, a field set in
// an api.ErrorResponse literal or one encoding/json writes whatever its value, and fails on a
// property the schema declares that none of them sends.
//
// A writer is read where it builds the envelope. Every mention of api.ErrorResponse in the auth
// server's production code must be a composite literal with keyed fields; any other, a variable
// declared of the type, a literal with positional fields, is reported rather than skipped, since
// which fields it sends cannot be read from it. The reverse, a field sent that the schema lacks, is
// TestOpenAPI_SchemaPropertiesMatchTheAPIStructs's forward direction.
//
// It reads files and nothing else.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/guard"
)

// coreAPIImportPath is the package declaring the envelope's Go type.
const coreAPIImportPath = "github.com/leodip/goiabada/core/api"

// errorEnvelopeSchema and errorEnvelopeType name the envelope in the spec and in core/api.
const (
	errorEnvelopeSchema = "ErrorResponse"
	errorEnvelopeType   = "ErrorResponse"
)

func TestOpenAPI_ErrorResponseDeclaresOnlyWhatTheWritersSend(t *testing.T) {
	assertErrorEnvelopeSent(t, web.OpenAPISpec(), guard.SourceRoot(t), "authserver", "core/api")
}

// errorEnvelopeFixtureStruct is core/api's envelope as the rule tests declare it: two omitempty
// fields and one encoding/json always writes.
const errorEnvelopeFixtureStruct = "package api\n\n" +
	"type ErrorResponse struct {\n" +
	"\tErrorCode        string         `json:\"error_code,omitempty\"`\n" +
	"\tErrorArgs        map[string]any `json:\"error_args,omitempty\"`\n" +
	"\tErrorDescription string         `json:\"error_description\"`\n" +
	"}\n"

// errorEnvelopeFixtureWriter builds the envelope the way apiresponse.WriteError does.
const errorEnvelopeFixtureWriter = "package apiresponse\n\n" +
	"import \"github.com/leodip/goiabada/core/api\"\n\n" +
	"func WriteError(code, message string) any {\n" +
	"\treturn api.ErrorResponse{ErrorCode: code, ErrorDescription: message}\n" +
	"}\n"

func errorEnvelopeFixtureSpec(properties ...string) []byte {
	var b strings.Builder
	b.WriteString("components:\n  schemas:\n    ErrorResponse:\n      type: object\n      properties:\n")
	for _, p := range properties {
		b.WriteString("        " + p + ":\n          type: string\n")
	}
	b.WriteString("    SuccessResponse:\n      type: object\n")
	return []byte(b.String())
}

func TestOpenAPI_AnErrorFieldNoWriterSendsFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "core/api/errors.go", errorEnvelopeFixtureStruct)
	writeDocFixture(t, root, "authserver/internal/apiresponse/apiresponse.go", errorEnvelopeFixtureWriter)
	writeDocFixture(t, root, "authserver/internal/handlers/other.go", "package handlers\n\n"+
		"import \"github.com/leodip/goiabada/core/api\"\n\n"+
		"func a() any {\n"+
		"\tvar e api.ErrorResponse\n"+
		"\treturn e\n"+
		"}\n\n"+
		"func b() any { return api.ErrorResponse{\"c\", map[string]any{\"k\": 1}, \"d\"} }\n")
	writeDocFixture(t, root, "authserver/internal/handlers/dot.go", "package handlers\n\n"+
		"import . \"github.com/leodip/goiabada/core/api\"\n\n"+
		"var _ = ErrorResponse{ErrorArgs: map[string]any{\"k\": 1}}\n")
	// A test file is not a writer, whatever it builds.
	writeDocFixture(t, root, "authserver/internal/apiresponse/apiresponse_test.go", "package apiresponse\n\n"+
		"import \"github.com/leodip/goiabada/core/api\"\n\n"+
		"var _ = api.ErrorResponse{ErrorArgs: map[string]any{\"k\": 1}}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorEnvelopeSent(r, errorEnvelopeFixtureSpec("error_code", "error_args", "error_description", "error_hint"),
			root, "authserver", "core/api")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"authserver/internal/handlers/dot.go: imports core/api with a dot, so its mentions of ErrorResponse cannot be read",
		"authserver/internal/handlers/other.go:6: mentions api.ErrorResponse outside a composite literal, so which fields it sends cannot be read",
		"authserver/internal/handlers/other.go:10: builds api.ErrorResponse with positional fields, so which fields it sends cannot be read",
		`openapi.yaml: the ErrorResponse schema declares "error_args", which no writer of api.ErrorResponse sends`,
		`openapi.yaml: the ErrorResponse schema declares "error_hint", which no writer of api.ErrorResponse sends`,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestOpenAPI_ErrorFieldsTheWritersSendPass(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "core/api/errors.go", errorEnvelopeFixtureStruct)
	// An aliased import and a pointer literal are both a writer. ErrorDescription is never set
	// here and still counts as sent, because encoding/json writes a field without omitempty
	// whatever its value.
	writeDocFixture(t, root, "authserver/internal/middleware/refuse.go", "package middleware\n\n"+
		"import wire \"github.com/leodip/goiabada/core/api\"\n\n"+
		"func refuse() any { return &wire.ErrorResponse{ErrorCode: \"TOO_MANY_REQUESTS\"} }\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorEnvelopeSent(r, errorEnvelopeFixtureSpec("error_code", "error_description"),
			root, "authserver", "core/api")
	})

	if report.Failed() {
		t.Errorf("an envelope the writers send in full failed: %+v", report)
	}
}

func TestOpenAPI_AnErrorEnvelopeCheckWithNoWriterStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "core/api/errors.go", errorEnvelopeFixtureStruct)
	writeDocFixture(t, root, "authserver/internal/apiresponse/apiresponse.go", "package apiresponse\n\n"+
		"func WriteError(code, message string) any { return nil }\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorEnvelopeSent(r, errorEnvelopeFixtureSpec("error_code", "error_description"),
			root, "authserver", "core/api")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no writer") {
		t.Errorf("a walk that reached no writer did not stop the check: %+v", report)
	}
}

func TestOpenAPI_AnErrorEnvelopeCheckWithNoSchemaStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "core/api/errors.go", errorEnvelopeFixtureStruct)
	writeDocFixture(t, root, "authserver/internal/apiresponse/apiresponse.go", errorEnvelopeFixtureWriter)

	report := guard.Run(func(r guard.Reporter) {
		assertErrorEnvelopeSent(r, []byte("components:\n  schemas:\n    SuccessResponse:\n      type: object\n"),
			root, "authserver", "core/api")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "ErrorResponse") {
		t.Errorf("a spec without the ErrorResponse schema did not stop the check naming it: %+v", report)
	}
}

func TestOpenAPI_AnErrorEnvelopeCheckWithNoStructStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "core/api/errors.go", "package api\n\ntype SuccessResponse struct{}\n")
	writeDocFixture(t, root, "authserver/internal/apiresponse/apiresponse.go", errorEnvelopeFixtureWriter)

	report := guard.Run(func(r guard.Reporter) {
		assertErrorEnvelopeSent(r, errorEnvelopeFixtureSpec("error_code", "error_description"),
			root, "authserver", "core/api")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "core/api declares no ErrorResponse") {
		t.Errorf("a core/api without the envelope did not stop the check: %+v", report)
	}
}

// assertErrorEnvelopeSent is the reporting half: one failure per finding of
// errorEnvelopeFindings, and a stop for a schema, a struct or a writer not found, since a check
// that compared nothing proves nothing.
func assertErrorEnvelopeSent(r guard.Reporter, spec []byte, srcRoot, writerDir, apiDir string) {
	r.Helper()
	findings, err := errorEnvelopeFindings(spec, srcRoot, writerDir, apiDir)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// errorEnvelopeFindings reads the ErrorResponse schema's properties from spec, api.ErrorResponse's
// fields from apiDir, and every production mention of api.ErrorResponse under writerDir, both
// relative to srcRoot. It returns one finding per mention it cannot read the fields of, then one
// per schema property no writer sends. It returns an error, and no findings, when the schema, the
// struct or any writer is not found.
func errorEnvelopeFindings(spec []byte, srcRoot, writerDir, apiDir string) ([]string, error) {
	properties, err := errorEnvelopeSchemaProperties(spec)
	if err != nil {
		return nil, err
	}
	fields, err := errorEnvelopeStructFields(filepath.Join(srcRoot, filepath.FromSlash(apiDir)), apiDir)
	if err != nil {
		return nil, err
	}

	var findings []string
	set := map[string]bool{} // Go field names some writer sets
	writers := 0
	walkErr := filepath.WalkDir(filepath.Join(srcRoot, filepath.FromSlash(writerDir)),
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(srcRoot, path)
			if relErr != nil {
				return relErr
			}
			fset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if parseErr != nil {
				return parseErr
			}
			local, imported := importName(file, coreAPIImportPath)
			if !imported {
				return nil
			}
			if local == "." {
				findings = append(findings, filepath.ToSlash(rel)+": imports core/api with a dot, so its "+
					"mentions of ErrorResponse cannot be read")
				return nil
			}
			isEnvelope := func(e ast.Expr) bool {
				sel, ok := e.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != errorEnvelopeType {
					return false
				}
				x, ok := sel.X.(*ast.Ident)
				return ok && x.Name == local
			}
			where := func(n ast.Node) string {
				return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), fset.Position(n.Pos()).Line)
			}

			// One pass in source order. Inspect reaches a literal before its type, so a type
			// already marked as a literal's is not counted again as a bare mention.
			literalTypes := map[ast.Expr]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok && isEnvelope(lit.Type) {
					literalTypes[lit.Type] = true
					var names []string
					for _, elt := range lit.Elts {
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							if key, isIdent := kv.Key.(*ast.Ident); isIdent {
								names = append(names, key.Name)
							}
						}
					}
					if len(names) != len(lit.Elts) {
						findings = append(findings, where(lit)+": builds api.ErrorResponse with positional "+
							"fields, so which fields it sends cannot be read")
						return true
					}
					writers++
					for _, name := range names {
						set[name] = true
					}
					return true
				}
				if e, ok := n.(ast.Expr); ok && isEnvelope(e) && !literalTypes[e] {
					findings = append(findings, where(e)+": mentions api.ErrorResponse outside a composite "+
						"literal, so which fields it sends cannot be read")
					return false
				}
				return true
			})
			return nil
		})
	if walkErr != nil {
		return nil, fmt.Errorf("walking %s for writers of api.ErrorResponse: %w", writerDir, walkErr)
	}
	if writers == 0 {
		return nil, fmt.Errorf("found no writer of api.ErrorResponse under %s; the walk is no longer "+
			"reaching the envelope's writers", writerDir)
	}

	sent := map[string]bool{}
	for goName, field := range fields {
		if !field.omitempty || set[goName] {
			sent[field.json] = true
		}
	}
	for _, property := range properties {
		if !sent[property] {
			findings = append(findings, fmt.Sprintf("openapi.yaml: the %s schema declares %q, which no writer of "+
				"api.%s sends", errorEnvelopeSchema, property, errorEnvelopeType))
		}
	}
	return findings, nil
}

// errorEnvelopeSchemaProperties returns the ErrorResponse schema's own properties, sorted. The
// schema is a plain object; one composed through allOf, $ref, oneOf or anyOf would have properties
// this does not read, so it is refused rather than read as declaring none.
func errorEnvelopeSchemaProperties(spec []byte) ([]string, error) {
	var doc struct {
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("parsing openapi.yaml: %w", err)
	}
	schema, found := doc.Components.Schemas[errorEnvelopeSchema]
	if !found {
		return nil, fmt.Errorf("openapi.yaml declares no %s schema", errorEnvelopeSchema)
	}
	var properties []string
	for i := 0; i+1 < len(schema.Content); i += 2 {
		key, value := schema.Content[i].Value, schema.Content[i+1]
		switch key {
		case "allOf", "$ref", "oneOf", "anyOf":
			return nil, fmt.Errorf("openapi.yaml's %s schema uses %s, which this check does not read",
				errorEnvelopeSchema, key)
		case "properties":
			for j := 0; j+1 < len(value.Content); j += 2 {
				properties = append(properties, value.Content[j].Value)
			}
		}
	}
	if len(properties) == 0 {
		return nil, fmt.Errorf("openapi.yaml's %s schema declares no properties", errorEnvelopeSchema)
	}
	slices.Sort(properties)
	return properties, nil
}

// envelopeField is one api.ErrorResponse field as encoding/json writes it.
type envelopeField struct {
	json      string
	omitempty bool
}

// errorEnvelopeStructFields reads api.ErrorResponse's marshalled fields from the package's
// production files, by Go name.
func errorEnvelopeStructFields(dir, display string) (map[string]envelopeField, error) {
	sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil, parseErr
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, isType := spec.(*ast.TypeSpec)
				if !isType || ts.Name.Name != errorEnvelopeType {
					continue
				}
				st, isStruct := ts.Type.(*ast.StructType)
				if !isStruct {
					return nil, fmt.Errorf("%s declares %s as something other than a struct", display, errorEnvelopeType)
				}
				fields := map[string]envelopeField{}
				for _, f := range st.Fields.List {
					if len(f.Names) == 0 {
						return nil, fmt.Errorf("%s's %s embeds a type, which this check does not read",
							display, errorEnvelopeType)
					}
					if name, omitempty, marshalled := jsonFieldName(f); marshalled {
						fields[f.Names[0].Name] = envelopeField{json: name, omitempty: omitempty}
					}
				}
				return fields, nil
			}
		}
	}
	return nil, fmt.Errorf("%s declares no %s struct", display, errorEnvelopeType)
}

// importName returns the name file binds path to, "." for a dot import, and false when it does not
// import it or imports it for its side effects alone.
func importName(file *ast.File, path string) (string, bool) {
	for _, spec := range file.Imports {
		value, err := strconv.Unquote(spec.Path.Value)
		if err != nil || value != path {
			continue
		}
		if spec.Name == nil {
			return path[strings.LastIndex(path, "/")+1:], true
		}
		if spec.Name.Name == "_" {
			return "", false
		}
		return spec.Name.Name, true
	}
	return "", false
}
