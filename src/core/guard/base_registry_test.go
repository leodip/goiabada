package guard

// The release Dockerfiles and the docs Dockerfile take their bases' registry from one build
// argument, baseRegistry, which defaults to Docker Hub's library, docker.io/library (#867 decision
// 6). A build that passes nothing, a release's, the Docs workflow's or a user's own docker build,
// builds on the images it always has. Check's builds pass the mirror, ghcr.io/leodip/goiabada-ci,
// so they pull nothing from Docker Hub: the docs job in both its builds, and Build validation. The
// builds that ship pass nothing: what users run is built on upstream's tag as it is when it is
// built, and trusts no registry but Docker Hub.
//
// The docs job waits for the Versions job, and runs its browser test on Node at tools.node, the
// version the docs image is built with, which version-manager.sh update writes into the docs
// Dockerfile's FROM line.

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// baseRegistryArg is the build argument a Dockerfile takes its bases' registry from.
	baseRegistryArg = "baseRegistry"
	// baseRegistryDefault is its default, Docker Hub's library, where the bases come from today.
	baseRegistryDefault = "docker.io/library"
	// ciMirror is the registry Check's builds pass, the mirror of #867.
	ciMirror = "ghcr.io/leodip/goiabada-ci"
)

// baseRegistryDockerfiles are the Dockerfiles that take baseRegistry, relative to the repository
// root.
var baseRegistryDockerfiles = []string{"src/build/Dockerfile-authserver", "src/build/Dockerfile-adminconsole", "site/Dockerfile"}

// baseRegistryBuilder is a file that builds some of baseRegistryDockerfiles, each named by its path
// relative to the repository root: Check, whose builds pass the mirror, or a build that ships,
// which passes no baseRegistry.
type baseRegistryBuilder struct {
	file        string
	dockerfiles []string
	mirror      bool
}

var baseRegistryBuilders = []baseRegistryBuilder{
	{file: checkWorkflow, dockerfiles: baseRegistryDockerfiles, mirror: true},
	// The Release workflow's Images job builds and pushes the release images with this script.
	{file: "src/build/build-docker-images.sh", dockerfiles: baseRegistryDockerfiles[:2]},
	{file: ".github/workflows/docs.yml", dockerfiles: baseRegistryDockerfiles[2:]},
}

// baseRegistryDockerfileFindings holds one Dockerfile to taking its bases' registry from
// baseRegistry: the argument declared before the first FROM, where a FROM can read it, with Docker
// Hub's library as its default, and every FROM that names an image, not scratch and not an earlier
// stage, naming it under ${baseRegistry}/.
func baseRegistryDockerfileFindings(rel, src string) []string {
	instructions, unparseable := dockerInstructions(src)
	if unparseable != "" {
		return []string{fmt.Sprintf("base registry: %s %s, which this reader does not parse the way Docker does", rel, unparseable)}
	}
	want := "ARG " + baseRegistryArg + "=" + baseRegistryDefault
	var findings []string
	declared, froms := false, 0
	stages := map[string]bool{}
	for _, in := range instructions {
		fields := strings.Fields(in.text)
		at := fmt.Sprintf("base registry: %s:%d", rel, in.line)
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			if froms > 0 {
				continue
			}
			for _, f := range fields[1:] {
				name, value, hasDefault := strings.Cut(f, "=")
				if name != baseRegistryArg {
					continue
				}
				declared = true
				if !hasDefault || value != baseRegistryDefault {
					findings = append(findings, fmt.Sprintf("%s declares ARG %s, where it must be %s, so a build that passes no %s pulls its bases from Docker Hub as it always has",
						at, f, want, baseRegistryArg))
				}
			}
		case "FROM":
			froms++
			image, name := "", ""
			for i := 1; i < len(fields); i++ {
				switch {
				case strings.HasPrefix(fields[i], "--"):
				case strings.EqualFold(fields[i], "AS") && i+1 < len(fields):
					name = strings.ToLower(fields[i+1])
					i++
				case image == "":
					image = fields[i]
				}
			}
			external := image != "scratch" && !stages[strings.ToLower(image)]
			if external && !strings.HasPrefix(image, "${"+baseRegistryArg+"}/") && !strings.HasPrefix(image, "$"+baseRegistryArg+"/") {
				findings = append(findings, fmt.Sprintf("%s builds on %s, which bypasses ${%s}, so a build passing %s pulls it from %s all the same: write FROM ${%s}/%s",
					at, image, baseRegistryArg, baseRegistryArg, imageRegistry(image), baseRegistryArg, image[strings.LastIndex(image, "/")+1:]))
			}
			if name != "" {
				stages[name] = true
			}
		}
	}
	if froms == 0 {
		return []string{fmt.Sprintf("base registry: %s has no FROM, so this check read no base", rel)}
	}
	if !declared {
		findings = append(findings, fmt.Sprintf("base registry: %s declares no %s before its first FROM, where a FROM can read it", rel, want))
	}
	return findings
}

// builtDockerfile returns which of dockerfiles a build's -f or --file names: one of them, or a path
// ending in /one of them, as a build run from another directory names it.
func builtDockerfile(named []string, dockerfiles []string) string {
	for _, f := range named {
		f = path.Clean(f)
		for _, d := range dockerfiles {
			if f == d || strings.HasSuffix(f, "/"+d) || strings.HasSuffix(d, "/"+f) && path.Base(f) != "Dockerfile" {
				return d
			}
		}
	}
	return ""
}

// baseRegistryBuildFindings reads one builder's shell scripts and holds each build of its
// Dockerfiles to the registry it must pass: Check's to --build-arg baseRegistry=<the mirror>,
// written out, and a build that ships to none, the file's scripts naming baseRegistry nowhere. It
// reports every build whose Dockerfile it cannot read, and each of the builder's Dockerfiles it
// finds no build of, since a check that read nothing would pass on any file.
func baseRegistryBuildFindings(b baseRegistryBuilder, scripts []shellSource) []string {
	var findings []string
	built := map[string]bool{}
	for _, src := range scripts {
		script := readShell(src.text)
		for _, p := range script.problems {
			findings = append(findings, fmt.Sprintf("base registry: %s:%d %s, which this reader cannot read as the shell would", b.file, src.offset+p.line, p.what))
		}
		if !b.mirror {
			for i, line := range strings.Split(script.bare, "\n") {
				if strings.Contains(line, baseRegistryArg) {
					findings = append(findings, fmt.Sprintf("base registry: %s:%d names %s, where a build that ships passes none and builds on Docker Hub's images, the default",
						b.file, src.offset+i+1, baseRegistryArg))
				}
			}
		}
		for _, c := range script.commands {
			args, ok := isDockerBuild(c)
			if !ok {
				continue
			}
			at := fmt.Sprintf("base registry: %s:%d", b.file, src.offset+c.line)
			named, dynamic := flagValues(args, "-f")
			long, longDynamic := flagValues(args, "--file")
			if dynamic || longDynamic {
				findings = append(findings, at+" names the Dockerfile it builds through an expansion, so this check cannot tell which it builds")
				continue
			}
			dockerfile := builtDockerfile(append(named, long...), b.dockerfiles)
			if dockerfile == "" {
				continue
			}
			built[dockerfile] = true
			if !b.mirror {
				continue
			}
			passed, writtenOut := []string{}, false
			for i := 0; i < len(args); i++ {
				word := args[i]
				if v, ok := strings.CutPrefix(word.value, "--build-arg="); ok {
					word.value = v
				} else if word.value == "--build-arg" && i+1 < len(args) {
					i++
					word = args[i]
				} else {
					continue
				}
				if value, ok := strings.CutPrefix(word.value, baseRegistryArg+"="); ok {
					passed = append(passed, value)
					// An expansion stays in the value as written, so the mirror's name is written out.
					writtenOut = writtenOut || value == ciMirror
				}
			}
			want := "--build-arg " + baseRegistryArg + "=" + ciMirror
			switch {
			case len(passed) == 0:
				findings = append(findings, fmt.Sprintf("%s builds %s without %s, so its bases come from Docker Hub", at, dockerfile, want))
			case len(passed) > 1 || !writtenOut:
				findings = append(findings, fmt.Sprintf("%s builds %s with %s=%s, where Check's builds pass %s, written out",
					at, dockerfile, baseRegistryArg, strings.Join(passed, " and "), want))
			}
		}
	}
	for _, d := range b.dockerfiles {
		if !built[d] {
			findings = append(findings, fmt.Sprintf("base registry: %s holds no build of %s this check can read", b.file, d))
		}
	}
	return findings
}

// checkBaseRegistries reads each Dockerfile and builder under the repository root and returns their
// findings and how many of the files it read. A Dockerfile a builder builds from the mirror is also
// held to bases the mirror holds, mirrored being the mirror addresses the list holds.
func checkBaseRegistries(repoRoot string, dockerfiles []string, builders []baseRegistryBuilder, mirrored map[string]bool) ([]string, int) {
	var findings []string
	read := 0
	fromMirror := map[string]bool{}
	for _, b := range builders {
		for _, d := range b.dockerfiles {
			fromMirror[d] = fromMirror[d] || b.mirror
		}
	}
	for _, rel := range dockerfiles {
		content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("base registry: %s cannot be read: %v", rel, err))
			continue
		}
		read++
		findings = append(findings, baseRegistryDockerfileFindings(rel, string(content))...)
		if fromMirror[rel] {
			findings = append(findings, mirrorBaseFindings("base registry", rel, string(content), mirrored)...)
		}
	}
	for _, b := range builders {
		content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(b.file)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("base registry: %s cannot be read: %v", b.file, err))
			continue
		}
		read++
		scripts := []shellSource{{text: string(content)}}
		if strings.HasSuffix(b.file, ".yml") || strings.HasSuffix(b.file, ".yaml") {
			scripts = workflowRunScripts(string(content))
		}
		findings = append(findings, baseRegistryBuildFindings(b, scripts)...)
	}
	return findings, read
}

// assertBaseRegistries is the base registry guard's reporting half: each finding of
// checkBaseRegistries an error, and a check that read none of its files under repoRoot, or has no
// mirror address to hold Check's bases to, fatal.
func assertBaseRegistries(r Reporter, repoRoot string, dockerfiles []string, builders []baseRegistryBuilder, mirrored map[string]bool) {
	r.Helper()
	if len(mirrored) == 0 {
		r.Fatalf("base registry: the mirror's list gave no address, so this check has nothing to hold Check's bases to")
	}
	findings, read := checkBaseRegistries(repoRoot, dockerfiles, builders, mirrored)
	reportBuildFileFindings(r, "base registry", repoRoot, read, findings)
}

// reportBuildFileFindings is the reporting half the guards of #867 that read the repository's
// build files share: a check that read none of its files under root would pass on any tree, so it
// is fatal, and each finding is an error.
func reportBuildFileFindings(r Reporter, guard, root string, read int, findings []string) {
	r.Helper()
	if read == 0 {
		r.Fatalf("%s: read none of its files under %s, so this check read nothing", guard, root)
	}
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// assertWorkflowFindings is the reporting half of a guard that reads one workflow under root: what
// finder finds in it, each an error, and a workflow that cannot be read, fatal.
func assertWorkflowFindings(r Reporter, guard, root, file string, finder func(file, text string) []string) {
	r.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		r.Fatalf("%s: %s cannot be read, so this check read nothing: %v", guard, file, err)
	}
	reportBuildFileFindings(r, guard, root, 1, finder(file, string(content)))
}

// repositoryTree copies files, relative to the repository root, as they are committed into an
// empty tree, with each of edits, a file's text and its replacement, applied once, and returns it.
func repositoryTree(t *testing.T, files []string, edits map[string][2]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range repositoryFiles(t, files) {
		if e, ok := edits[name]; ok {
			require.Equal(t, 1, strings.Count(content, e[0]), "%s: %s", name, e[0])
			content = strings.Replace(content, e[0], e[1], 1)
		}
		writeFixture(t, root, name, content)
	}
	return root
}

// committedMirrored are the mirror addresses the list holds at the committed pins.
func committedMirrored(t *testing.T) map[string]bool {
	t.Helper()
	return mirroredAddresses(t, repositoryFiles(t, []string{"src/authserver/versions.yaml"})["src/authserver/versions.yaml"])
}

// baseRegistryFiles are the files the base registry guard reads.
func baseRegistryFiles() []string {
	files := slices.Clone(baseRegistryDockerfiles)
	for _, b := range baseRegistryBuilders {
		files = append(files, b.file)
	}
	return files
}

func TestBaseRegistry_TheDockerfilesDefaultToDockerHubAndOnlyChecksBuildsPassTheMirror(t *testing.T) {
	assertBaseRegistries(t, filepath.Dir(SourceRoot(t)), baseRegistryDockerfiles, baseRegistryBuilders, committedMirrored(t))
}

// The reporting half passes the files as they are committed, reports a docs image built on a tag
// the mirror lacks, which Check's docs build would ask the mirror for, and is fatal on a tree it
// read nothing of and on a list that gave no address.
func TestBaseRegistry_Reporting(t *testing.T) {
	mirrored := committedMirrored(t)
	assertTree := func(root string, m map[string]bool) Report {
		return Run(func(r Reporter) { assertBaseRegistries(r, root, baseRegistryDockerfiles, baseRegistryBuilders, m) })
	}
	t.Run("the committed files pass", func(t *testing.T) {
		report := assertTree(repositoryTree(t, baseRegistryFiles(), nil), mirrored)
		assert.False(t, report.Failed(), "%s", report.Text())
	})
	t.Run("a docs image on a tag the mirror lacks fails", func(t *testing.T) {
		root := repositoryTree(t, baseRegistryFiles(), map[string][2]string{
			"site/Dockerfile": {"FROM ${baseRegistry}/nginx:alpine", "FROM ${baseRegistry}/nginx:latest"},
		})
		report := assertTree(root, mirrored)
		assert.False(t, report.Stopped, "a finding is an error, not a fatal: %s", report.Text())
		require.Len(t, report.Errors, 1, "%s", report.Text())
		assert.Contains(t, report.Errors[0], "base registry: site/Dockerfile:")
		assert.Contains(t, report.Errors[0], "builds on ${baseRegistry}/nginx:latest, which a build passing the mirror pulls as ghcr.io/leodip/goiabada-ci/nginx:latest, and .github/mirror/images does not hold it")
	})
	t.Run("a tree holding none of the files is fatal", func(t *testing.T) {
		report := assertTree(t.TempDir(), mirrored)
		require.True(t, report.Stopped, "an empty walk passed: %s", report.Text())
		assert.Contains(t, report.Fatal, "base registry: read none of its files under")
	})
	t.Run("a list that gave no address is fatal", func(t *testing.T) {
		report := assertTree(repositoryTree(t, baseRegistryFiles(), nil), map[string]bool{})
		require.True(t, report.Stopped, "%s", report.Text())
		assert.Contains(t, report.Fatal, "the mirror's list gave no address")
	})
}

func TestBaseRegistry_DockerfileFindings(t *testing.T) {
	const rel = "build/Dockerfile-one"
	const dockerfile = "# A comment.\n" + // 1
		"ARG baseRegistry=docker.io/library\n" + // 2
		"FROM --platform=$BUILDPLATFORM ${baseRegistry}/golang:1.28.0-alpine AS build\n" + // 3
		"ARG version\n" + // 4
		"RUN go build ./cmd/one\n" + // 5
		"FROM build AS tested\n" + // 6
		"FROM $baseRegistry/nginx:alpine AS serve\n" + // 7
		"FROM scratch AS final\n" + // 8
		"COPY --from=build /one /one\n" // 9
	edit := func(old, replacement string) string {
		require.Equal(t, 1, strings.Count(dockerfile, old), old)
		return strings.Replace(dockerfile, old, replacement, 1)
	}
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"bases under ${baseRegistry} or $baseRegistry, a stage and scratch pass", dockerfile, nil},
		{
			"a base written with Docker Hub's name",
			edit("${baseRegistry}/golang:1.28.0-alpine", "golang:1.28.0-alpine"),
			[]string{"base registry: build/Dockerfile-one:3 builds on golang:1.28.0-alpine, which bypasses ${baseRegistry}, so a build passing baseRegistry pulls it from docker.io all the same: write FROM ${baseRegistry}/golang:1.28.0-alpine"},
		},
		{
			"a base written with another registry",
			edit("$baseRegistry/nginx:alpine", "ghcr.io/leodip/goiabada-ci/nginx:alpine"),
			[]string{"base registry: build/Dockerfile-one:7 builds on ghcr.io/leodip/goiabada-ci/nginx:alpine, which bypasses ${baseRegistry}, so a build passing baseRegistry pulls it from ghcr.io all the same: write FROM ${baseRegistry}/nginx:alpine"},
		},
		{
			"a stage named only later is an image when an earlier FROM names it",
			edit("FROM build AS tested", "FROM tested AS build2"),
			[]string{"base registry: build/Dockerfile-one:6 builds on tested, which bypasses ${baseRegistry}"},
		},
		{
			"no default leaves the bases' registry empty",
			edit("ARG baseRegistry=docker.io/library", "ARG baseRegistry"),
			[]string{"base registry: build/Dockerfile-one:2 declares ARG baseRegistry, where it must be ARG baseRegistry=docker.io/library, so a build that passes no baseRegistry pulls its bases from Docker Hub as it always has"},
		},
		{
			"the mirror as the default would build what ships from it",
			edit("ARG baseRegistry=docker.io/library", "ARG baseRegistry="+ciMirror),
			[]string{"base registry: build/Dockerfile-one:2 declares ARG baseRegistry=ghcr.io/leodip/goiabada-ci, where it must be ARG baseRegistry=docker.io/library"},
		},
		{
			"the argument declared in a stage is not one a FROM reads",
			strings.Replace(edit("ARG baseRegistry=docker.io/library\n", ""), "ARG version", "ARG version baseRegistry=docker.io/library", 1),
			[]string{"base registry: build/Dockerfile-one declares no ARG baseRegistry=docker.io/library before its first FROM"},
		},
		{
			"a Dockerfile Docker reads differently",
			"# escape=`\n" + dockerfile,
			[]string{"base registry: build/Dockerfile-one sets the escape directive, which this reader does not parse the way Docker does"},
		},
		{
			"a file with no FROM read nothing",
			"ARG baseRegistry=docker.io/library\n",
			[]string{"base registry: build/Dockerfile-one has no FROM, so this check read no base"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertFindings(t, baseRegistryDockerfileFindings(rel, c.src), c.want...)
		})
	}
}

func TestBaseRegistry_BuildFindings(t *testing.T) {
	check := baseRegistryBuilder{file: "check.yml", dockerfiles: []string{"build/Dockerfile-one", "site/Dockerfile"}, mirror: true}
	ships := baseRegistryBuilder{file: "build.sh", dockerfiles: []string{"build/Dockerfile-one", "site/Dockerfile"}}
	const workflow = "jobs:\n" + // 1
		"  docs:\n" + // 2
		"    steps:\n" + // 3
		"      - run: docker build --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci -f site/Dockerfile .\n" + // 4
		"      - run: docker build -f .devcontainer/Dockerfile .\n" + // 5
		"      - working-directory: build\n" + // 6
		"        run: |\n" + // 7
		"          args=(--build-arg \"version=$V\")\n" + // 8
		"          docker buildx build --load \"${args[@]}\" --build-arg \"baseRegistry=ghcr.io/leodip/goiabada-ci\" --file Dockerfile-one -t one ..\n" // 9
	const script = "#!/bin/bash\n" + // 1
		"docker buildx build --build-arg version=$VERSION \\\n" + // 2
		"  -f ./build/Dockerfile-one --push .\n" + // 3
		"# Built on Docker Hub's images: no baseRegistry here.\n" + // 4
		"docker build -f site/Dockerfile .\n" // 5
	workflowFindings := func(src string) []string { return baseRegistryBuildFindings(check, workflowRunScripts(src)) }
	scriptFindings := func(src string) []string { return baseRegistryBuildFindings(ships, []shellSource{{text: src}}) }
	edit := func(t *testing.T, src, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(src, old), old)
		return strings.Replace(src, old, with, 1)
	}

	t.Run("Check's builds passing the mirror written out pass, and its other builds are not these", func(t *testing.T) {
		assertFindings(t, workflowFindings(workflow))
	})
	t.Run("a build that ships naming no baseRegistry passes", func(t *testing.T) {
		assertFindings(t, scriptFindings(script))
	})
	t.Run("a Check build passing no baseRegistry", func(t *testing.T) {
		assertFindings(t, workflowFindings(edit(t, workflow, "--build-arg baseRegistry=ghcr.io/leodip/goiabada-ci ", "")),
			"base registry: check.yml:4 builds site/Dockerfile without --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, so its bases come from Docker Hub")
	})
	t.Run("a Check build passing Docker Hub", func(t *testing.T) {
		assertFindings(t, workflowFindings(edit(t, workflow, "\"baseRegistry=ghcr.io/leodip/goiabada-ci\"", "baseRegistry=docker.io/library")),
			"base registry: check.yml:9 builds build/Dockerfile-one with baseRegistry=docker.io/library, where Check's builds pass --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, written out")
	})
	t.Run("a Check build passing the mirror through a variable", func(t *testing.T) {
		assertFindings(t, workflowFindings(edit(t, workflow, "\"baseRegistry=ghcr.io/leodip/goiabada-ci\"", "\"baseRegistry=$MIRROR\"")),
			"base registry: check.yml:9 builds build/Dockerfile-one with baseRegistry=$MIRROR, where Check's builds pass --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, written out")
	})
	t.Run("a Check build passing the mirror only inside an array is not read", func(t *testing.T) {
		src := edit(t, edit(t, workflow, " --build-arg \"baseRegistry=ghcr.io/leodip/goiabada-ci\"", ""),
			"args=(", "args=(--build-arg baseRegistry=ghcr.io/leodip/goiabada-ci ")
		assertFindings(t, workflowFindings(src),
			"base registry: check.yml:9 builds build/Dockerfile-one without --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci")
	})
	t.Run("a Check build passing the mirror and then another registry", func(t *testing.T) {
		assertFindings(t, workflowFindings(edit(t, workflow, "--file Dockerfile-one", "--build-arg=baseRegistry=docker.io/library --file Dockerfile-one")),
			"base registry: check.yml:9 builds build/Dockerfile-one with baseRegistry=ghcr.io/leodip/goiabada-ci and docker.io/library")
	})
	t.Run("a build that ships passing the mirror", func(t *testing.T) {
		assertFindings(t, scriptFindings(edit(t, script, "version=$VERSION", "version=$VERSION --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci")),
			"base registry: build.sh:2 names baseRegistry, where a build that ships passes none and builds on Docker Hub's images, the default")
	})
	t.Run("a build that ships passing it through an array", func(t *testing.T) {
		assertFindings(t, scriptFindings(edit(t, script, "#!/bin/bash\n", "#!/bin/bash\nargs=(--build-arg \"baseRegistry=$REGISTRY\")\n")),
			"base registry: build.sh:2 names baseRegistry")
	})
	t.Run("a Dockerfile named through a variable", func(t *testing.T) {
		assertFindings(t, scriptFindings(script+"docker build -f \"$dockerfile\" .\n"),
			"base registry: build.sh:6 names the Dockerfile it builds through an expansion")
	})
	t.Run("a file building neither Dockerfile read nothing", func(t *testing.T) {
		assertFindings(t, workflowFindings("jobs:\n  b:\n    steps:\n      - run: ./build.sh\n"),
			"base registry: check.yml holds no build of build/Dockerfile-one this check can read",
			"base registry: check.yml holds no build of site/Dockerfile this check can read")
	})
	t.Run("a script the reader cannot read", func(t *testing.T) {
		got := scriptFindings(script + "echo \"unclosed\n")
		assert.Contains(t, strings.Join(got, "\n"), "base registry: build.sh:6 opens a \" that never closes")
	})
	t.Run("a file that cannot be read", func(t *testing.T) {
		got, read := checkBaseRegistries(t.TempDir(), []string{"site/Dockerfile"}, []baseRegistryBuilder{check}, fixtureMirrored())
		assert.Zero(t, read)
		assertFindings(t, got,
			"base registry: site/Dockerfile cannot be read",
			"base registry: check.yml cannot be read")
	})
}

// nodePin is tools.node as versions.yaml writes it.
func nodePin(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(SourceRoot(t), "authserver", "versions.yaml"))
	require.NoError(t, err)
	match := regexp.MustCompile(`(?m)^  node: "([0-9]+\.[0-9]+\.[0-9]+)"$`).FindSubmatch(content)
	require.NotNil(t, match, "versions.yaml has no tools.node written as X.Y.Z")
	return string(match[1])
}

// docsJobFindings holds Check's docs job to waiting for the Versions job, which checks the mirror
// before the job's first pull, and to running its browser test on Node at the Versions job's node
// output, rather than on a version read from the docs Dockerfile, whose FROM line baseRegistry
// changes.
func docsJobFindings(file, text string) []string {
	lines := workflowLines(text)
	numbers, ok := workflowJobs(lines)["docs"]
	if !ok {
		return []string{fmt.Sprintf("base registry: %s has no docs job", file)}
	}
	const wantNode = "${{ needs.versions.outputs.node }}"
	var findings []string
	needs, setupNode := false, 0
	uses := ""
	for _, n := range numbers {
		line := lines[n-1]
		trimmed := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "    needs:"); ok {
			for _, job := range strings.FieldsFunc(v, func(r rune) bool { return r == '[' || r == ']' || r == ',' || r == ' ' }) {
				needs = needs || job == "versions"
			}
		}
		if strings.HasPrefix(line, "      - ") {
			uses = ""
		}
		if m := workflowUses.FindStringSubmatch(line); m != nil {
			uses = m[1]
		}
		if v, ok := strings.CutPrefix(trimmed, "node-version:"); ok && strings.HasPrefix(uses, "actions/setup-node@") {
			setupNode = n
			if got := yamlLineScalar(strings.TrimSpace(v)); got != wantNode {
				findings = append(findings, fmt.Sprintf("base registry: %s:%d runs the docs browser test on Node %s, where it must be %s, the version the docs image is built with",
					file, n, got, wantNode))
			}
		}
	}
	if !needs {
		findings = append(findings, fmt.Sprintf("base registry: %s:%d (docs) does not need versions, so it can pull its bases before the Versions job has run", file, numbers[0]))
	}
	if setupNode == 0 {
		findings = append(findings, fmt.Sprintf("base registry: %s:%d (docs) sets up no Node with actions/setup-node, so its browser test runs on the runner's own", file, numbers[0]))
	}
	return findings
}

func TestCheckWorkflow_TheDocsJobWaitsForVersionsAndRunsTheDocsImagesNode(t *testing.T) {
	files := repositoryFiles(t, []string{checkWorkflow, "site/Dockerfile"})
	assertWorkflowFindings(t, "base registry", filepath.Dir(SourceRoot(t)), checkWorkflow, docsJobFindings)
	assert.Contains(t, files["site/Dockerfile"], "${baseRegistry}/node:"+nodePin(t)+"-alpine AS sources",
		"site/Dockerfile does not build on Node at tools.node, the Node the docs job's browser test runs on; run ./version-manager.sh update")
}

func TestCheckWorkflow_DocsJobFindings(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  versions:\n" + // 2
		"    runs-on: ubuntu-latest\n" + // 3
		"  docs:\n" + // 4
		"    needs: [lint, versions]\n" + // 5
		"    steps:\n" + // 6
		"      - uses: actions/setup-node@0000000000000000000000000000000000000000 # v7\n" + // 7
		"        with:\n" + // 8
		"          node-version: ${{ needs.versions.outputs.node }}\n" + // 9
		"      - uses: actions/setup-python@0000000000000000000000000000000000000000 # v6\n" + // 10
		"        with:\n" + // 11
		"          python-version: '3.14'\n" // 12
	edit := func(t *testing.T, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(workflow, old), old)
		return strings.Replace(workflow, old, with, 1)
	}
	t.Run("a docs job that needs versions and sets up its Node passes", func(t *testing.T) {
		assertFindings(t, docsJobFindings("check.yml", workflow))
		assertFindings(t, docsJobFindings("check.yml", edit(t, "needs: [lint, versions]", "needs: versions")))
	})
	t.Run("a docs job that does not wait for Versions", func(t *testing.T) {
		assertFindings(t, docsJobFindings("check.yml", edit(t, "    needs: [lint, versions]\n", "")),
			"base registry: check.yml:4 (docs) does not need versions, so it can pull its bases before the Versions job has run")
	})
	t.Run("a Node read from the Dockerfile's FROM line", func(t *testing.T) {
		assertFindings(t, docsJobFindings("check.yml", edit(t, "${{ needs.versions.outputs.node }}", "${{ steps.node.outputs.version }}")),
			"base registry: check.yml:9 runs the docs browser test on Node ${{ steps.node.outputs.version }}, where it must be ${{ needs.versions.outputs.node }}")
	})
	t.Run("no Node set up", func(t *testing.T) {
		assertFindings(t, docsJobFindings("check.yml", edit(t, "actions/setup-node@", "actions/setup-go@")),
			"base registry: check.yml:4 (docs) sets up no Node with actions/setup-node")
	})
	t.Run("no docs job", func(t *testing.T) {
		assertFindings(t, docsJobFindings("check.yml", "jobs:\n  versions:\n    runs-on: ubuntu-latest\n"),
			"base registry: check.yml has no docs job")
	})
}

// update writes the Go and Node pins into the FROM lines of the three Dockerfiles as they are
// committed, under ${baseRegistry}, and changes no other line of them.
func TestVersionManagerUpdate_WritesThePinsIntoTheBaseRegistryFromLines(t *testing.T) {
	assertUpdateWritesFromLines(t, map[string][]string{
		"src/build/Dockerfile-authserver": {
			"FROM --platform=$BUILDPLATFORM ${baseRegistry}/golang:1.28.0-alpine AS build",
			"FROM --platform=$BUILDPLATFORM ${baseRegistry}/golang:1.28.0-alpine AS certs",
		},
		"src/build/Dockerfile-adminconsole": {
			"FROM --platform=$BUILDPLATFORM ${baseRegistry}/golang:1.28.0-alpine AS build",
			"FROM --platform=$BUILDPLATFORM ${baseRegistry}/golang:1.28.0-alpine AS certs",
		},
		"site/Dockerfile": {"FROM ${baseRegistry}/node:27.0.1-alpine AS sources", "FROM sources AS builder", "FROM ${baseRegistry}/nginx:alpine"},
	})
}

// assertUpdateWritesFromLines copies each file of want, relative to the repository root, as it is
// committed, into an empty tree, runs update there with tools.go at 1.28.0 and tools.node at
// 27.0.1, and holds each file's lines that begin FROM, but FROM scratch, to want's, and every other
// line to what it was. Each file declares ARG baseRegistry=docker.io/library. update's other steps
// are replaced: the pins come from the test rather than versions.yaml, and nothing is fetched.
func assertUpdateWritesFromLines(t *testing.T, want map[string][]string) {
	t.Helper()
	files := map[string]string{}
	base := t.TempDir()
	for rel := range want {
		files[rel] = repositoryFiles(t, []string{rel})[rel]
		writeFixture(t, base, rel, files[rel])
	}
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	out, err := exec.Command("bash", "-c", `. "$1" || exit 1; BASE_DIR="$2"
		require_yq() { :; }
		get_version() { case "$1" in tools.go) echo 1.28.0 ;; tools.node) echo 27.0.1 ;; *) echo 0.0.0 ;; esac; }
		vendor_fetch() { :; }
		update_mailpit() { :; }
		cmd_update`, "bash", script, base).CombinedOutput()
	require.NoError(t, err, "%s", out)

	for rel, before := range files {
		content, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(rel)))
		require.NoError(t, err)
		var gotFrom []string
		beforeLines, afterLines := strings.Split(before, "\n"), strings.Split(string(content), "\n")
		require.Len(t, afterLines, len(beforeLines), "%s: update added or removed lines", rel)
		for i, line := range afterLines {
			if strings.HasPrefix(line, "FROM ") && !strings.HasPrefix(line, "FROM scratch") {
				gotFrom = append(gotFrom, line)
				continue
			}
			assert.Equal(t, beforeLines[i], line, "%s:%d changed, and it is no base's FROM", rel, i+1)
		}
		assert.Equal(t, want[rel], gotFrom, "%s's FROM lines after update", rel)
		assert.True(t, slices.Contains(beforeLines, "ARG baseRegistry=docker.io/library"), "%s declares no ARG baseRegistry=docker.io/library", rel)
	}
}
