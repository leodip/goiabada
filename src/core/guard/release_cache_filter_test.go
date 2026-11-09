package guard

// The release images copy their CA bundle from a refresh stage, certs, which upgrades it from a
// freshly fetched Alpine index (#808). apk's --no-cache keeps no index on disk but does nothing
// against Docker's layer cache, so a build that reuses its cache ships the bundle an earlier build
// fetched, however old. Excluding the refresh stage alone is not enough either: it then reruns,
// but the final stage's COPY of its file is cached on the stage's definition and still ships the
// earlier bundle. So every build of a release image, the release's build script and CI's build
// validation, excludes both stages from the cache, --no-cache-filter naming certs and final, which
// reruns the refresh and ships what it fetched while the Go build stays cached. This test reads
// those builds as the shell runs them and holds each to that. That the bundle is fresh is shown by
// content, on a built image; this shows only that every release build asks for it.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// releaseImageBuilders are the files that build the release images, relative to the repository
// root: the script a release pushes them with, and the workflow whose build validation builds and
// smoke-runs them.
var releaseImageBuilders = []string{"src/build/build-docker-images.sh", ".github/workflows/check.yml"}

// refreshCacheFilter is the stages every release image build excludes from the cache.
var refreshCacheFilter = []string{"certs", "final"}

// releaseDockerfileNames are the release Dockerfiles' base names, which a build names with -f.
var releaseDockerfileNames = []string{"Dockerfile-authserver", "Dockerfile-adminconsole"}

// shellSource is one shell script in a file, and the file line it begins on less one, which turns a
// line of the script into a line of the file.
type shellSource struct {
	offset int
	text   string
}

// workflowRunScripts returns every run: script of a GitHub workflow.
func workflowRunScripts(text string) []shellSource {
	var out []shellSource
	for _, run := range workflowRuns(workflowLines(text)) {
		out = append(out, run.script)
	}
	return out
}

// workflowLines splits a workflow into its lines.
func workflowLines(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}

// yamlLineScalar is the string a one-line YAML scalar holds: a single-quoted one without its quotes
// and with each doubled quote read as one, a double-quoted one unescaped, and a plain one as
// written.
func yamlLineScalar(value string) string {
	switch {
	case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'")
	case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}
	return value
}

// workflowRun is one run: key of a workflow: the line it is on, counted from 0, the column its name
// begins at, and its script.
type workflowRun struct {
	line, column int
	script       shellSource
}

// workflowRuns returns every run: key of a GitHub workflow and its script, each a block scalar
// (run: |) or one line. A block runs while its lines are indented deeper than the run key, blank
// lines included, and is dedented by its first line's indentation, as YAML reads it.
func workflowRuns(lines []string) []workflowRun {
	var out []workflowRun
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimLeft(lines[i], " ")
		key := len(lines[i]) - len(trimmed)
		if rest, ok := strings.CutPrefix(trimmed, "- "); ok {
			trimmed, key = rest, key+2
		}
		value, ok := strings.CutPrefix(trimmed, "run:")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" && !strings.HasPrefix(value, "|") && !strings.HasPrefix(value, ">") {
			out = append(out, workflowRun{line: i, column: key, script: shellSource{offset: i, text: yamlLineScalar(value)}})
			continue
		}
		var block []string
		indent := -1
		j := i + 1
		for ; j < len(lines); j++ {
			body := strings.TrimLeft(lines[j], " ")
			depth := len(lines[j]) - len(body)
			if body != "" && depth <= key {
				break
			}
			if body != "" && indent < 0 {
				indent = depth
			}
			if len(lines[j]) >= indent && indent >= 0 {
				block = append(block, lines[j][indent:])
			} else {
				block = append(block, "")
			}
		}
		out = append(out, workflowRun{line: i, column: key, script: shellSource{offset: i + 1, text: strings.Join(block, "\n")}})
		i = j - 1
	}
	return out
}

// isDockerBuild reports whether a command is docker build or docker buildx build, and returns the
// words after it.
func isDockerBuild(c shellCommand) ([]shellWord, bool) {
	w := c.words
	switch {
	case len(w) >= 2 && w[0].value == "docker" && w[1].value == "build":
		return w[2:], true
	case len(w) >= 3 && w[0].value == "docker" && w[1].value == "buildx" && w[2].value == "build":
		return w[3:], true
	}
	return nil, false
}

// flagValues returns the values a command's arguments give the long flag name, whether as the next
// word or after an equals sign, and whether any of them is an expansion.
func flagValues(args []shellWord, name string) ([]string, bool) {
	var values []string
	expands := false
	for i := 0; i < len(args); i++ {
		if v, ok := strings.CutPrefix(args[i].value, name+"="); ok {
			values, expands = append(values, v), expands || args[i].expands
			continue
		}
		if args[i].value == name && i+1 < len(args) {
			values, expands = append(values, args[i+1].value), expands || args[i+1].expands
			i++
		}
	}
	return values, expands
}

// cacheFilterFindings reads one file's shell scripts and returns every build of a release image in
// it that does not exclude refreshCacheFilter's stages from the cache, every build whose Dockerfile
// it cannot read, and a finding when it holds no build of either image, since a check that read
// nothing would pass on any file.
func cacheFilterFindings(file string, scripts []shellSource) []string {
	var findings []string
	built := map[string]bool{}
	for _, src := range scripts {
		script := readShell(src.text)
		for _, p := range script.problems {
			findings = append(findings, fmt.Sprintf("cache filter: %s:%d %s, which this reader cannot read as the shell would", file, src.offset+p.line, p.what))
		}
		for _, c := range script.commands {
			args, ok := isDockerBuild(c)
			if !ok {
				continue
			}
			at := fmt.Sprintf("cache filter: %s:%d", file, src.offset+c.line)
			dockerfiles, dynamic := flagValues(args, "-f")
			long, longDynamic := flagValues(args, "--file")
			dockerfiles = append(dockerfiles, long...)
			if dynamic || longDynamic {
				findings = append(findings, at+" names the Dockerfile it builds through an expansion, so this check cannot tell whether it builds a release image")
				continue
			}
			name := ""
			for _, f := range dockerfiles {
				if base := path.Base(f); slices.Contains(releaseDockerfileNames, base) {
					name = base
				}
			}
			if name == "" {
				continue
			}
			built[name] = true
			filters, _ := flagValues(args, "--no-cache-filter")
			var stages []string
			for _, f := range filters {
				stages = append(stages, strings.Split(f, ",")...)
			}
			for _, stage := range refreshCacheFilter {
				if slices.Contains(stages, stage) {
					continue
				}
				why := "so it reuses a cached certificate refresh and ships the CA bundle an earlier build fetched"
				if stage == "final" {
					why = "so even a rerun refresh is shipped from the final stage's cache, with the CA bundle an earlier build fetched"
				}
				findings = append(findings, fmt.Sprintf("%s builds %s without --no-cache-filter %s, %s", at, name, stage, why))
			}
		}
	}
	for _, name := range releaseDockerfileNames {
		if !built[name] {
			findings = append(findings, fmt.Sprintf("cache filter: %s holds no build of %s this check can read, where it builds the release images", file, name))
		}
	}
	return findings
}

// checkCacheFilters reads each release image builder under the repository root, a workflow's run
// scripts or a whole shell script, and returns cacheFilterFindings for each.
func checkCacheFilters(repoRoot string, files []string) []string {
	var findings []string
	for _, rel := range files {
		content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("cache filter: %s cannot be read: %v", rel, err))
			continue
		}
		scripts := []shellSource{{text: string(content)}}
		if strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml") {
			scripts = workflowRunScripts(string(content))
		}
		findings = append(findings, cacheFilterFindings(rel, scripts)...)
	}
	return findings
}

func TestReleaseBuilds_TheRealImageBuildsRerunTheRefresh(t *testing.T) {
	assert.Empty(t, checkCacheFilters(filepath.Dir(SourceRoot(t)), releaseImageBuilders))
}

func TestReleaseBuilds_CacheFilter(t *testing.T) {
	const script = "#!/bin/bash\n" +
		"set -euo pipefail\n" +
		"docker buildx build --progress=plain \\\n" +
		"  --no-cache-filter certs --no-cache-filter final \\\n" +
		"  -f ./build/Dockerfile-authserver --push .\n" +
		"docker buildx build --no-cache-filter=certs,final -f ./build/Dockerfile-adminconsole --push .\n"
	const workflow = "jobs:\n" +
		"  build-validation:\n" +
		"    steps:\n" +
		"      - name: Build the docs image\n" +
		"        run: docker build -f site/Dockerfile -t docs .\n" +
		"      - name: Build both images\n" +
		"        run: |\n" +
		"          set -euo pipefail\n" +
		"          args=(--build-arg \"version=$V\")\n" +
		"\n" +
		"          docker buildx build --load \"${args[@]}\" --no-cache-filter certs --no-cache-filter final -f Dockerfile-authserver -t a ..\n" +
		"          docker buildx build --load \"${args[@]}\" --no-cache-filter certs --no-cache-filter final --file Dockerfile-adminconsole -t b ..\n" +
		"      - run: echo done\n"
	scriptFindings := func(src string) []string {
		return cacheFilterFindings("build.sh", []shellSource{{text: src}})
	}
	workflowFindings := func(src string) []string {
		return cacheFilterFindings("check.yml", workflowRunScripts(src))
	}
	replace := func(t *testing.T, src, old, with string) string {
		t.Helper()
		if strings.Count(src, old) != 1 {
			t.Fatalf("%q is not in the fixture exactly once", old)
		}
		return strings.Replace(src, old, with, 1)
	}

	t.Run("the script with both filters, as two flags or one list, passes", func(t *testing.T) {
		assertFindings(t, scriptFindings(script))
	})
	t.Run("the workflow's builds with both filters pass, and its other builds are not release images", func(t *testing.T) {
		assertFindings(t, workflowFindings(workflow))
	})
	t.Run("a build without the refresh stage's filter", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "--no-cache-filter certs ", "")),
			"cache filter: build.sh:3 builds Dockerfile-authserver without --no-cache-filter certs, so it reuses a cached certificate refresh")
	})
	t.Run("a build without the final stage's filter", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "=certs,final", "=certs")),
			"cache filter: build.sh:6 builds Dockerfile-adminconsole without --no-cache-filter final, so even a rerun refresh is shipped from the final stage's cache")
	})
	t.Run("a build with neither", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "  --no-cache-filter certs --no-cache-filter final \\\n", "")),
			"build.sh:3 builds Dockerfile-authserver without --no-cache-filter certs",
			"build.sh:3 builds Dockerfile-authserver without --no-cache-filter final")
	})
	t.Run("--no-cache, which also rebuilds the Go stage, is not the filter", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "--no-cache-filter=certs,final", "--no-cache")),
			"build.sh:6 builds Dockerfile-adminconsole without --no-cache-filter certs",
			"build.sh:6 builds Dockerfile-adminconsole without --no-cache-filter final")
	})
	t.Run("a filter naming another stage", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "--no-cache-filter final", "--no-cache-filter build")),
			"build.sh:3 builds Dockerfile-authserver without --no-cache-filter final")
	})
	t.Run("the filter in a comment is not on the command", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script,
			"  --no-cache-filter certs --no-cache-filter final \\\n  -f ./build/Dockerfile-authserver --push .\n",
			"  -f ./build/Dockerfile-authserver --push . # --no-cache-filter certs --no-cache-filter final\n")),
			"build.sh:3 builds Dockerfile-authserver without --no-cache-filter certs",
			"build.sh:3 builds Dockerfile-authserver without --no-cache-filter final")
	})
	t.Run("the filters echoed rather than passed", func(t *testing.T) {
		assertFindings(t, scriptFindings(replace(t, script, "--no-cache-filter=certs,final -f", "-f")+"echo --no-cache-filter certs --no-cache-filter final\n"),
			"build.sh:6 builds Dockerfile-adminconsole without --no-cache-filter certs",
			"build.sh:6 builds Dockerfile-adminconsole without --no-cache-filter final")
	})
	t.Run("a workflow build without the filters, its line the file's", func(t *testing.T) {
		assertFindings(t, workflowFindings(replace(t, workflow, "--no-cache-filter certs --no-cache-filter final --file", "--file")),
			"cache filter: check.yml:12 builds Dockerfile-adminconsole without --no-cache-filter certs",
			"cache filter: check.yml:12 builds Dockerfile-adminconsole without --no-cache-filter final")
	})
	t.Run("a build naming its Dockerfile through a variable", func(t *testing.T) {
		assertFindings(t, scriptFindings(script+"docker buildx build -f \"$dockerfile\" .\n"),
			"cache filter: build.sh:7 names the Dockerfile it builds through an expansion")
	})
	t.Run("a file building neither image", func(t *testing.T) {
		assertFindings(t, scriptFindings("#!/bin/bash\ndocker buildx build -f site/Dockerfile .\n"),
			"cache filter: build.sh holds no build of Dockerfile-authserver",
			"cache filter: build.sh holds no build of Dockerfile-adminconsole")
	})
	t.Run("a workflow whose builds moved out of its run scripts", func(t *testing.T) {
		assertFindings(t, workflowFindings("jobs:\n  b:\n    steps:\n      - run: ./build.sh\n"),
			"holds no build of Dockerfile-authserver",
			"holds no build of Dockerfile-adminconsole")
	})
	t.Run("a script the reader cannot read", func(t *testing.T) {
		got := scriptFindings(script + "echo \"unclosed\n")
		assert.Contains(t, strings.Join(got, "\n"), "cache filter: build.sh:7 opens a \" that never closes")
	})
	t.Run("a file that cannot be read", func(t *testing.T) {
		assertFindings(t, checkCacheFilters(t.TempDir(), []string{"src/build/build-docker-images.sh"}),
			"cache filter: src/build/build-docker-images.sh cannot be read")
	})
}

// The workflow reader over the shapes check.yml writes a run in.
func TestWorkflowRunScripts(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  a:\n" + // 2
		"    steps:\n" + // 3
		"      - run: echo one\n" + // 4
		"      - name: two\n" + // 5
		"        working-directory: src\n" + // 6
		"        run: |\n" + // 7
		"          set -e\n" + // 8
		"\n" + // 9
		"          if true; then\n" + // 10
		"            echo two\n" + // 11
		"          fi\n" + // 12
		"      - name: three\n" + // 13
		"        run: |-\n" + // 14
		"          echo three\n" + // 15
		"  b:\n" + // 16
		"    steps:\n" // 17
	got := workflowRunScripts(workflow)
	assert.Equal(t, []shellSource{
		{offset: 3, text: "echo one"},
		{offset: 7, text: "set -e\n\nif true; then\n  echo two\nfi"},
		{offset: 14, text: "echo three"},
	}, got)
}
