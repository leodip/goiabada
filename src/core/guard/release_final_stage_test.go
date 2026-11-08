package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The release images are built FROM scratch (#808): each holds its server's binary, the CA bundle
// the servers' TLS reads, /tmp and, in the auth server's, the two folders it writes, and nothing an
// image scanner could report or a compromised process could run. No Go test can build an image, so
// this test holds the release Dockerfiles to the form that gives those contents, and the smoke test
// CI runs on the built images to the same list of them, which it compares with each image's own.

// releaseDockerfiles are the release images' Dockerfiles, relative to the source root.
var releaseDockerfiles = []string{"build/Dockerfile-authserver", "build/Dockerfile-adminconsole"}

// imageSmokeTest is the script CI runs on the images it builds, relative to the source root. It
// declares each image's contents in an array of its own, which it compares with what the image holds.
const imageSmokeTest = "build/smoke-test-images.sh"

// releaseImage is one release image: its Dockerfile, the server whose binary it runs, the
// instruction its build stage lays out the image's folders with, the smoke test's array declaring
// its contents, and those contents, each "<mode> <uid>/<gid> <path>" as tar lists an export of it.
type releaseImage struct {
	dockerfile string
	server     string
	layout     string
	smokeList  string
	contents   []string
}

// releaseImages are the two images, and the one list of what each holds. /app and its binary are
// root's and not writable by 10001, so the server cannot replace what the next start runs; /tmp is
// world-writable and sticky, as on any Linux system; /data, where the wizard's Compose file mounts
// the SQLite volume, and /bootstrap, where the legacy bootstrap file is written, are 10001's, since
// Docker copies a mount point's ownership into an empty named volume.
var releaseImages = []releaseImage{
	{
		dockerfile: "build/Dockerfile-authserver",
		server:     "authserver",
		layout: "RUN mkdir -p /app/rootfs/tmp /app/rootfs/data /app/rootfs/bootstrap && chmod 1777 /app/rootfs/tmp && " +
			"chown 10001:10001 /app/rootfs/data /app/rootfs/bootstrap",
		smokeList: "AUTHSERVER_CONTENTS",
		contents: []string{
			"drwxr-xr-x 0/0 app/",
			"-rwxr-xr-x 0/0 app/goiabada-authserver",
			"drwxr-xr-x 10001/10001 bootstrap/",
			"drwxr-xr-x 10001/10001 data/",
			"drwxr-xr-x 0/0 etc/",
			"drwxr-xr-x 0/0 etc/ssl/",
			"drwxr-xr-x 0/0 etc/ssl/certs/",
			"-rw-r--r-- 0/0 etc/ssl/certs/ca-certificates.crt",
			"drwxrwxrwt 0/0 tmp/",
		},
	},
	{
		dockerfile: "build/Dockerfile-adminconsole",
		server:     "adminconsole",
		layout:     "RUN mkdir -p /app/rootfs/tmp && chmod 1777 /app/rootfs/tmp",
		smokeList:  "ADMINCONSOLE_CONTENTS",
		contents: []string{
			"drwxr-xr-x 0/0 app/",
			"-rwxr-xr-x 0/0 app/goiabada-adminconsole",
			"drwxr-xr-x 0/0 etc/",
			"drwxr-xr-x 0/0 etc/ssl/",
			"drwxr-xr-x 0/0 etc/ssl/certs/",
			"-rw-r--r-- 0/0 etc/ssl/certs/ca-certificates.crt",
			"drwxrwxrwt 0/0 tmp/",
		},
	},
}

const (
	// caBundle is where the image holds the CA bundle, the path Go's crypto/x509 reads first on
	// Linux and the one an operator's mount or SSL_CERT_FILE replaces.
	caBundle = "/etc/ssl/certs/ca-certificates.crt"
	// refreshCommand is the certificate refresh stage's one instruction: it upgrades the Go image's
	// CA bundle from a freshly fetched index, and fails the build when it cannot fetch one.
	refreshCommand = "RUN apk upgrade --no-cache ca-certificates-bundle"
	// finalStageFrom opens the image's stage: an empty base, named final for the release builds'
	// --no-cache-filter.
	finalStageFrom = "FROM scratch AS final"
	// imageUser is the image's user, numeric so a Kubernetes runAsNonRoot can verify it without a
	// passwd file, which the image has none of.
	imageUser = "USER 10001:10001"
)

// finalStage is the image stage of server's Dockerfile, instruction by instruction after its FROM:
// the folders the build stage laid out, the CA bundle from the refresh stage, the binary, and the
// user, health check and entrypoint the image runs it with.
func finalStage(server string) []string {
	binary := "/app/goiabada-" + server
	return []string{
		"COPY --from=build /app/rootfs/ /",
		"COPY --from=certs " + caBundle + " " + caBundle,
		"COPY --from=build /app/bin/goiabada-" + server + " " + binary,
		"WORKDIR /app",
		imageUser,
		imageHealthcheck(server),
		`ENTRYPOINT ["` + binary + `"]`,
	}
}

// imageHealthcheck is the health check each image declares (#808): its server's own healthcheck
// command, with the timings the wizard's Compose file gives the auth server.
func imageHealthcheck(server string) string {
	return `HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --retries=3 CMD ["/app/goiabada-` + server + `", "healthcheck"]`
}

// dockerInstruction is one instruction of a Dockerfile as Docker reads it: the text with its
// continuation lines joined and the comment lines inside a continuation dropped, and the line it
// begins on.
type dockerInstruction struct {
	text string
	line int
}

// escapeDirective is the parser directive that changes the continuation character.
var escapeDirective = regexp.MustCompile(`(?i)^#\s*escape\s*=`)

// dockerInstructions splits a Dockerfile into its instructions as Docker does without heredocs and
// with the default escape character: a line ending in a backslash continues the instruction, and a
// comment line or an empty line inside a continuation is dropped. What it cannot read as Docker
// does, a heredoc or an escape directive, it reports as unparseable rather than guess at: BuildKit
// keeps a heredoc's terminator untrimmed and an escape directive can turn a backtick into the
// continuation, and either can make a line read as an instruction here while Docker reads it as
// file content or an argument (#542).
func dockerInstructions(src string) ([]dockerInstruction, string) {
	var out []dockerInstruction
	continuing := false
	for n, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") && escapeDirective.MatchString(trimmed) {
			return nil, "sets the escape directive"
		}
		switch {
		case continuing:
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			current := &out[len(out)-1]
			current.text += " " + strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		default:
			out = append(out, dockerInstruction{text: strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")), line: n + 1})
		}
		continuing = strings.HasSuffix(trimmed, "\\")
		// Any "<<" is refused, a heredoc of whatever delimiter BuildKit accepts, digits included,
		// and a here-string with it.
		if strings.Contains(trimmed, "<<") {
			return nil, "uses a heredoc, or << in some other form"
		}
	}
	return out, ""
}

// dockerStage is one stage of a Dockerfile: its FROM, the name it is given after AS, lowercased as
// Docker compares it, the image it starts from, and its instructions after the FROM.
type dockerStage struct {
	from         dockerInstruction
	name, image  string
	instructions []dockerInstruction
}

// dockerStages splits a Dockerfile's instructions into stages, each opened by a FROM. Each
// instruction's text is normalized: its words single-spaced and its keyword upper-cased, as Docker
// reads keywords in any case.
func dockerStages(instructions []dockerInstruction) []dockerStage {
	var stages []dockerStage
	for _, in := range instructions {
		fields := strings.Fields(in.text)
		fields[0] = strings.ToUpper(fields[0])
		in.text = strings.Join(fields, " ")
		if fields[0] != "FROM" {
			if len(stages) > 0 {
				stages[len(stages)-1].instructions = append(stages[len(stages)-1].instructions, in)
			}
			continue
		}
		st := dockerStage{from: in}
		for i := 1; i < len(fields); i++ {
			switch {
			case strings.HasPrefix(fields[i], "--"):
			case strings.EqualFold(fields[i], "AS") && i+1 < len(fields):
				st.name = strings.ToLower(fields[i+1])
				i++
			case st.image == "":
				st.image = fields[i]
			}
		}
		stages = append(stages, st)
	}
	return stages
}

// stageNamed returns the stage the Dockerfile names name, or nil.
func stageNamed(stages []dockerStage, name string) *dockerStage {
	for i := range stages {
		if stages[i].name == name {
			return &stages[i]
		}
	}
	return nil
}

// keyword is an instruction's first word, upper-cased by dockerStages.
func keyword(in dockerInstruction) string {
	k, _, _ := strings.Cut(in.text, " ")
	return k
}

// finalStageFindings is every way the release Dockerfiles under root, and the smoke test beside
// them, disagree with the scratch image #808 holds them to: the last stage FROM scratch AS final
// holding exactly finalStage's instructions, the CA bundle copied from a refresh stage named certs
// on the builder's platform, the folders laid out in the build stage, and the smoke test declaring
// each image's contents as releaseImages lists them. It reads instructions as Docker does, so what
// counts is an instruction of a stage, not a line that looks like one.
func finalStageFindings(root string, images []releaseImage) ([]string, error) {
	smoke, err := os.ReadFile(filepath.Join(root, imageSmokeTest))
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s", imageSmokeTest)
	}
	var findings []string
	for _, img := range images {
		findings = append(findings, smokeListFindings(string(smoke), img)...)
	}

	for _, img := range images {
		src, err := os.ReadFile(filepath.Join(root, img.dockerfile))
		if err != nil {
			return nil, errs.Wrapf(err, "reading %s", img.dockerfile)
		}
		instructions, unparseable := dockerInstructions(string(src))
		if unparseable != "" {
			findings = append(findings, img.dockerfile+" "+unparseable+", which this test does not parse the way Docker does, "+
				"so it cannot tell what the image holds: write the release Dockerfiles without it")
			continue
		}
		stages := dockerStages(instructions)
		if len(stages) == 0 {
			return nil, errs.Errorf("%s has no FROM instruction", img.dockerfile)
		}
		findings = append(findings, imageStageFindings(img, stages[len(stages)-1])...)
		findings = append(findings, refreshStageFindings(img.dockerfile, stages)...)
		findings = append(findings, layoutFindings(img, stages)...)
	}
	return findings, nil
}

// imageStageFindings holds the last stage, the image, to FROM scratch AS final and exactly
// finalStage's instructions after it.
func imageStageFindings(img releaseImage, last dockerStage) []string {
	rel := img.dockerfile
	if !strings.EqualFold(last.from.text, finalStageFrom) {
		return []string{fmt.Sprintf("%s's last stage, the image, is %s, where it must be %s: an empty base, "+
			"named final for the release builds' --no-cache-filter", rel, last.from.text, finalStageFrom)}
	}
	var findings []string
	want := finalStage(img.server)
	left := slices.Clone(want)
	seen := map[string]int{}
	bundleReported := false
	for _, in := range last.instructions {
		k := keyword(in)
		seen[k]++
		if i := slices.Index(left, in.text); i >= 0 {
			left = slices.Delete(left, i, i+1)
			continue
		}
		switch {
		case k == "RUN":
			findings = append(findings, fmt.Sprintf("%s:%d runs %s in its final stage, where nothing can run it: the image "+
				"holds no shell or other program but the server, so do that work in an earlier stage and COPY its result in",
				rel, in.line, in.text))
		case k == "USER":
			findings = append(findings, fmt.Sprintf("%s:%d sets %s, where the image must run as %s, the numeric ids a "+
				"Kubernetes runAsNonRoot can verify without a passwd file", rel, in.line, in.text, imageUser))
		case k == "HEALTHCHECK":
			findings = append(findings, fmt.Sprintf("%s:%d declares %s, where it must declare exactly %s", rel, in.line,
				in.text, imageHealthcheck(img.server)))
		case k == "COPY" && strings.Contains(in.text, "ca-certificates.crt"):
			bundleReported = true
			findings = append(findings, fmt.Sprintf("%s:%d copies the CA bundle with %s, where it must copy it from the "+
				"refresh stage, which every release build reruns: %s", rel, in.line, in.text, want[1]))
		default:
			findings = append(findings, fmt.Sprintf("%s:%d holds %s in its final stage, which is not part of the image: "+
				"the stage holds exactly %s", rel, in.line, in.text, strings.Join(want, "; ")))
		}
	}
	for _, missing := range left {
		switch k, _, _ := strings.Cut(missing, " "); {
		case k == "USER" && seen[k] == 0:
			findings = append(findings, fmt.Sprintf("%s sets no USER in its final stage, so the server would run as root: "+
				"it must set %s", rel, imageUser))
		case k == "HEALTHCHECK" && seen[k] == 0:
			findings = append(findings, fmt.Sprintf("%s declares no HEALTHCHECK in its final stage: it must declare %s",
				rel, imageHealthcheck(img.server)))
		case k == "USER" || k == "HEALTHCHECK" || missing == want[1] && bundleReported:
			// Already reported as the instruction that stands in its place.
		default:
			findings = append(findings, fmt.Sprintf("%s's final stage lacks %s", rel, missing))
		}
	}
	return findings
}

// refreshStageFindings holds the Dockerfile to a certificate refresh stage named certs, on the
// builder's platform and from the build stage's own Go image, running refreshCommand alone.
func refreshStageFindings(rel string, stages []dockerStage) []string {
	build := stageNamed(stages, "build")
	if build == nil {
		return []string{rel + " has no stage named build, whose image the certificate refresh stage starts from"}
	}
	from := "FROM --platform=$BUILDPLATFORM " + build.image + " AS certs"
	certs := stageNamed(stages, "certs")
	if certs == nil {
		return []string{fmt.Sprintf("%s has no certificate refresh stage, %s then %s, for the image to copy its CA "+
			"bundle from", rel, from, refreshCommand)}
	}
	var findings []string
	if !strings.EqualFold(certs.from.text, from) {
		findings = append(findings, fmt.Sprintf("%s:%d opens its refresh stage with %s, where it must be %s: on the "+
			"builder's platform, since the bundle is the same on every one, and from the build stage's image",
			rel, certs.from.line, certs.from.text, from))
	}
	var body []string
	for _, in := range certs.instructions {
		body = append(body, in.text)
	}
	if !slices.Equal(body, []string{refreshCommand}) {
		findings = append(findings, fmt.Sprintf("%s:%d's refresh stage runs %s, where it must run exactly %s and nothing "+
			"else", rel, certs.from.line, strings.Join(body, "; "), refreshCommand))
	}
	return findings
}

// layoutFindings holds the build stage to laying out the image's folders, once, with the
// instruction releaseImages gives the image, which the final stage copies whole.
func layoutFindings(img releaseImage, stages []dockerStage) []string {
	build := stageNamed(stages, "build")
	if build == nil {
		return nil // refreshStageFindings reports it
	}
	n := 0
	for _, in := range build.instructions {
		if in.text == img.layout {
			n++
		}
	}
	switch n {
	case 0:
		return []string{fmt.Sprintf("%s's build stage does not lay out the image's folders with %s", img.dockerfile, img.layout)}
	case 1:
		return nil
	}
	return []string{fmt.Sprintf("%s's build stage lays out the image's folders more than once", img.dockerfile)}
}

// smokeListFindings holds the smoke test's array for img to img's contents, in any order.
func smokeListFindings(smoke string, img releaseImage) []string {
	got, ok := smokeTestList(smoke, img.smokeList)
	if !ok {
		return []string{fmt.Sprintf("%s declares no %s=( ... ) array, so it cannot hold CI's %s image to its contents: "+
			"it must list exactly %s", imageSmokeTest, img.smokeList, img.server, strings.Join(img.contents, ", "))}
	}
	var extra, missing []string
	for _, e := range got {
		if !slices.Contains(img.contents, e) {
			extra = append(extra, e)
		}
	}
	for _, e := range img.contents {
		if !slices.Contains(got, e) {
			missing = append(missing, e)
		}
	}
	var findings []string
	if len(extra) > 0 {
		findings = append(findings, fmt.Sprintf("%s's %s lists %s, which the %s image does not hold", imageSmokeTest,
			img.smokeList, strings.Join(extra, ", "), img.server))
	}
	if len(missing) > 0 {
		findings = append(findings, fmt.Sprintf("%s's %s lacks %s, which the %s image holds", imageSmokeTest,
			img.smokeList, strings.Join(missing, ", "), img.server))
	}
	return findings
}

// smokeArrayEntry is one double-quoted entry of a smoke test array.
var smokeArrayEntry = regexp.MustCompile(`"([^"]*)"`)

// smokeTestList reads the array the smoke test assigns name, over as many lines as it runs: its
// double-quoted entries up to the closing parenthesis. ok is false when it assigns none.
func smokeTestList(src, name string) ([]string, bool) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	offset := 0
	for _, line := range strings.SplitAfter(src, "\n") {
		if strings.HasPrefix(line, name+"=(") {
			body := src[offset+len(name)+2:]
			end := strings.IndexByte(body, ')')
			if end < 0 {
				return nil, false
			}
			var out []string
			for _, m := range smokeArrayEntry.FindAllStringSubmatch(body[:end], -1) {
				out = append(out, m[1])
			}
			return out, true
		}
		offset += len(line)
	}
	return nil, false
}

func TestReleaseDockerfiles_TheImagesAreScratch(t *testing.T) {
	findings, err := finalStageFindings(SourceRoot(t), releaseImages)
	require.NoError(t, err)
	for _, f := range findings {
		t.Error(f)
	}
}

// The finder over fixture trees, one case per way a release Dockerfile or the smoke test can be
// wrong, and the ways they are right. The fixture image is "one", its Dockerfile and contents
// written out here rather than taken from releaseImages.
func TestFinalStageFindings(t *testing.T) {
	const rel = "build/Dockerfile-one"
	one := releaseImage{
		dockerfile: rel,
		server:     "one",
		layout:     "RUN mkdir -p /app/rootfs/tmp && chmod 1777 /app/rootfs/tmp",
		smokeList:  "ONE_CONTENTS",
		contents:   []string{"drwxr-xr-x 0/0 app/", "-rwxr-xr-x 0/0 app/goiabada-one", "drwxrwxrwt 0/0 tmp/"},
	}
	const dockerfile = "FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build\n" +
		"RUN mkdir -p /app/rootfs/tmp \\\n" +
		"    && chmod 1777 /app/rootfs/tmp\n" +
		"RUN CGO_ENABLED=0 go build -o /app/bin/goiabada-one ./cmd/one\n" +
		"\n" +
		"FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs\n" +
		"RUN apk upgrade --no-cache ca-certificates-bundle\n" +
		"\n" +
		"FROM scratch AS final\n" +
		"COPY --from=build /app/rootfs/ /\n" +
		"COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n" +
		"COPY --from=build /app/bin/goiabada-one /app/goiabada-one\n" +
		"WORKDIR /app\n" +
		"USER 10001:10001\n" +
		`HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --retries=3 CMD ["/app/goiabada-one", "healthcheck"]` + "\n" +
		`ENTRYPOINT ["/app/goiabada-one"]` + "\n"
	const smoke = "#!/bin/bash\nONE_CONTENTS=(\n" +
		"    \"drwxr-xr-x 0/0 app/\"\n" +
		"    \"-rwxr-xr-x 0/0 app/goiabada-one\"\n" +
		"    \"drwxrwxrwt 0/0 tmp/\"\n" +
		")\nOTHER=(\"x\")\n"
	findingsOf := func(t *testing.T, dockerfileSrc, smokeSrc string) []string {
		t.Helper()
		root := t.TempDir()
		writeFixture(t, root, imageSmokeTest, smokeSrc)
		writeFixture(t, root, rel, dockerfileSrc)
		got, err := finalStageFindings(root, []releaseImage{one})
		require.NoError(t, err)
		return got
	}
	edit := func(old, replacement string) string {
		require.Equal(t, 1, strings.Count(dockerfile, old), old)
		return strings.Replace(dockerfile, old, replacement, 1)
	}

	cases := []struct {
		name       string
		dockerfile string
		smoke      string
		want       []string
	}{
		{"the scratch form passes", dockerfile, smoke, nil},
		{
			"CRLF line endings, lowercase keywords and extra spacing pass",
			strings.ReplaceAll(strings.NewReplacer(
				"FROM scratch AS final", "from scratch as final",
				"USER 10001:10001", "user   10001:10001",
				"FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs", "from --platform=$BUILDPLATFORM golang:1.27.3-alpine as certs",
			).Replace(dockerfile), "\n", "\r\n"),
			strings.ReplaceAll(smoke, "\n", "\r\n"),
			nil,
		},
		{
			"an Alpine final stage is not an empty base",
			edit("FROM scratch AS final", "FROM alpine:3.24 AS final"),
			smoke,
			[]string{"build/Dockerfile-one's last stage, the image, is FROM alpine:3.24 AS final, where it must be FROM scratch AS final"},
		},
		{
			"a scratch stage not named final escapes the cache filter",
			edit("FROM scratch AS final", "FROM scratch"),
			smoke,
			[]string{"build/Dockerfile-one's last stage, the image, is FROM scratch, where it must be FROM scratch AS final: an empty base, named final for the release builds' --no-cache-filter"},
		},
		{
			"a RUN in the final stage has nothing to run it",
			edit("WORKDIR /app\n", "WORKDIR /app\nRUN [\"/app/goiabada-one\", \"migrate\"]\n"),
			smoke,
			[]string{`build/Dockerfile-one:14 runs RUN ["/app/goiabada-one", "migrate"] in its final stage, where nothing can run it`},
		},
		{
			"no USER runs the server as root",
			edit("USER 10001:10001\n", ""),
			smoke,
			[]string{"build/Dockerfile-one sets no USER in its final stage, so the server would run as root: it must set USER 10001:10001"},
		},
		{
			"a named USER is not one runAsNonRoot can verify",
			edit("USER 10001:10001", "USER goiabada"),
			smoke,
			[]string{"build/Dockerfile-one:14 sets USER goiabada, where the image must run as USER 10001:10001"},
		},
		{
			"root as USER",
			edit("USER 10001:10001", "USER 0:0"),
			smoke,
			[]string{"build/Dockerfile-one:14 sets USER 0:0, where the image must run as USER 10001:10001"},
		},
		{
			"a second USER after the first",
			edit("ENTRYPOINT", "USER 0\nENTRYPOINT"),
			smoke,
			[]string{"build/Dockerfile-one:16 sets USER 0, where the image must run as USER 10001:10001"},
		},
		{
			"no HEALTHCHECK",
			edit(`HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --retries=3 CMD ["/app/goiabada-one", "healthcheck"]`+"\n", ""),
			smoke,
			[]string{`build/Dockerfile-one declares no HEALTHCHECK in its final stage: it must declare HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --retries=3 CMD ["/app/goiabada-one", "healthcheck"]`},
		},
		{
			"a HEALTHCHECK with no start period",
			edit("--start-period=300s ", ""),
			smoke,
			[]string{`build/Dockerfile-one:15 declares HEALTHCHECK --interval=10s --timeout=5s --retries=3 CMD ["/app/goiabada-one", "healthcheck"], where it must declare exactly`},
		},
		{
			"a HEALTHCHECK with a start interval, which Docker 24's builders refuse",
			edit("--retries=3", "--start-interval=2s --retries=3"),
			smoke,
			[]string{"build/Dockerfile-one:15 declares HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --start-interval=2s --retries=3"},
		},
		{
			"a HEALTHCHECK running wget",
			edit(`CMD ["/app/goiabada-one", "healthcheck"]`, `CMD ["wget", "--spider", "http://localhost:9090/health"]`),
			smoke,
			[]string{`build/Dockerfile-one:15 declares HEALTHCHECK --interval=10s --timeout=5s --start-period=300s --retries=3 CMD ["wget", "--spider", "http://localhost:9090/health"], where`},
		},
		{
			"the CA bundle copied from the build stage's cached image",
			edit("COPY --from=certs", "COPY --from=build"),
			smoke,
			[]string{"build/Dockerfile-one:11 copies the CA bundle with COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt, where it must copy it from the refresh stage, which every release build reruns"},
		},
		{
			"the CA bundle not copied at all",
			edit("COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n", ""),
			smoke,
			[]string{"build/Dockerfile-one's final stage lacks COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt"},
		},
		{
			"the folders not copied",
			edit("COPY --from=build /app/rootfs/ /\n", ""),
			smoke,
			[]string{"build/Dockerfile-one's final stage lacks COPY --from=build /app/rootfs/ /"},
		},
		{
			"a program copied in beside the server",
			edit("WORKDIR /app\n", "WORKDIR /app\nCOPY --from=build /bin/busybox /bin/sh\n"),
			smoke,
			[]string{"build/Dockerfile-one:14 holds COPY --from=build /bin/busybox /bin/sh in its final stage, which is not part of the image"},
		},
		{
			"another entrypoint",
			edit(`ENTRYPOINT ["/app/goiabada-one"]`, `ENTRYPOINT ["/app/goiabada-one", "serve"]`),
			smoke,
			[]string{
				`build/Dockerfile-one:16 holds ENTRYPOINT ["/app/goiabada-one", "serve"] in its final stage, which is not part of the image`,
				`build/Dockerfile-one's final stage lacks ENTRYPOINT ["/app/goiabada-one"]`,
			},
		},
		{
			"no certificate refresh stage",
			strings.Replace(edit("FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs\nRUN apk upgrade --no-cache ca-certificates-bundle\n", ""),
				"COPY --from=certs", "COPY --from=build", 1),
			smoke,
			[]string{
				"build/Dockerfile-one:9 copies the CA bundle with COPY --from=build",
				"build/Dockerfile-one has no certificate refresh stage, FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs then RUN apk upgrade --no-cache ca-certificates-bundle",
			},
		},
		{
			"a refresh stage under the target's emulation",
			edit("FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs", "FROM golang:1.27.3-alpine AS certs"),
			smoke,
			[]string{"build/Dockerfile-one:6 opens its refresh stage with FROM golang:1.27.3-alpine AS certs, where it must be FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs"},
		},
		{
			"a refresh stage from another image than the build stage's",
			edit("FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS certs", "FROM --platform=$BUILDPLATFORM alpine:3.24 AS certs"),
			smoke,
			[]string{"build/Dockerfile-one:6 opens its refresh stage with FROM --platform=$BUILDPLATFORM alpine:3.24 AS certs, where it must be"},
		},
		{
			"a refresh that does not upgrade the bundle",
			edit("RUN apk upgrade --no-cache ca-certificates-bundle", "RUN true"),
			smoke,
			[]string{"build/Dockerfile-one:6's refresh stage runs RUN true, where it must run exactly RUN apk upgrade --no-cache ca-certificates-bundle and nothing else"},
		},
		{
			"a refresh that adds a package beside the bundle",
			edit("RUN apk upgrade --no-cache ca-certificates-bundle", "RUN apk upgrade --no-cache ca-certificates-bundle\nRUN apk add --no-cache busybox-static"),
			smoke,
			[]string{"build/Dockerfile-one:6's refresh stage runs RUN apk upgrade --no-cache ca-certificates-bundle; RUN apk add --no-cache busybox-static, where"},
		},
		{
			"the folders not laid out",
			edit("RUN mkdir -p /app/rootfs/tmp \\\n    && chmod 1777 /app/rootfs/tmp\n", ""),
			smoke,
			[]string{"build/Dockerfile-one's build stage does not lay out the image's folders with RUN mkdir -p /app/rootfs/tmp && chmod 1777 /app/rootfs/tmp"},
		},
		{
			"/tmp laid out without its sticky bit",
			edit("chmod 1777", "chmod 777"),
			smoke,
			[]string{"build/Dockerfile-one's build stage does not lay out the image's folders"},
		},
		{
			"the folders laid out twice",
			edit("RUN CGO_ENABLED=0", "RUN mkdir -p /app/rootfs/tmp && chmod 1777 /app/rootfs/tmp\nRUN CGO_ENABLED=0"),
			smoke,
			[]string{"build/Dockerfile-one's build stage lays out the image's folders more than once"},
		},
		{
			"no build stage",
			strings.Replace(dockerfile, "AS build", "AS compile", 1),
			smoke,
			[]string{"build/Dockerfile-one has no stage named build"},
		},
		{
			"a heredoc, which this reader does not parse",
			edit("WORKDIR /app\n", "COPY <<EOF /note\nRUN x\nEOF\nWORKDIR /app\n"),
			smoke,
			[]string{"build/Dockerfile-one uses a heredoc"},
		},
		{
			"the escape directive",
			"# escape=`\n" + dockerfile,
			smoke,
			[]string{"build/Dockerfile-one sets the escape directive"},
		},
		{
			"the smoke test declaring no array for the image",
			dockerfile,
			"#!/bin/bash\nOTHER=(\"x\")\n",
			[]string{"build/smoke-test-images.sh declares no ONE_CONTENTS=( ... ) array, so it cannot hold CI's one image to its contents"},
		},
		{
			"the smoke test listing one more entry",
			dockerfile,
			strings.Replace(smoke, "    \"drwxrwxrwt 0/0 tmp/\"\n", "    \"drwxrwxrwt 0/0 tmp/\"\n    \"-rwxr-xr-x 0/0 bin/sh\"\n", 1),
			[]string{"build/smoke-test-images.sh's ONE_CONTENTS lists -rwxr-xr-x 0/0 bin/sh, which the one image does not hold"},
		},
		{
			"the smoke test leaving one out",
			dockerfile,
			strings.Replace(smoke, "    \"drwxrwxrwt 0/0 tmp/\"\n", "", 1),
			[]string{"build/smoke-test-images.sh's ONE_CONTENTS lacks drwxrwxrwt 0/0 tmp/, which the one image holds"},
		},
		{
			"the smoke test giving /tmp another mode",
			dockerfile,
			strings.Replace(smoke, "drwxrwxrwt 0/0 tmp/", "drwxrwxrwx 0/0 tmp/", 1),
			[]string{
				"lists drwxrwxrwx 0/0 tmp/, which the one image does not hold",
				"lacks drwxrwxrwt 0/0 tmp/, which the one image holds",
			},
		},
		{
			"the smoke test's array on one line, in another order",
			dockerfile,
			"ONE_CONTENTS=(\"drwxrwxrwt 0/0 tmp/\" \"drwxr-xr-x 0/0 app/\" \"-rwxr-xr-x 0/0 app/goiabada-one\")\n",
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertFindings(t, findingsOf(t, c.dockerfile, c.smoke), c.want...)
		})
	}

	t.Run("a smoke test but no Dockerfile", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, imageSmokeTest, smoke)
		_, err := finalStageFindings(root, []releaseImage{one})
		require.Error(t, err)
	})
	t.Run("no smoke test", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, rel, dockerfile)
		_, err := finalStageFindings(root, []releaseImage{one})
		require.Error(t, err)
	})
}

// The two images' lists, read against each other: the auth server's holds the admin console's
// entries, its own binary in place of the console's, and the two folders it writes.
func TestReleaseImages_TheAuthServerAddsItsTwoFolders(t *testing.T) {
	require.Len(t, releaseImages, 2)
	auth, console := releaseImages[0], releaseImages[1]
	var added []string
	for _, e := range auth.contents {
		if !slices.Contains(console.contents, e) {
			added = append(added, e)
		}
	}
	assert.Equal(t, []string{
		"-rwxr-xr-x 0/0 app/goiabada-authserver",
		"drwxr-xr-x 10001/10001 bootstrap/",
		"drwxr-xr-x 10001/10001 data/",
	}, added)
}
