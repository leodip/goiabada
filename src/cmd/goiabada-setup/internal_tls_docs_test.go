package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
	"go.yaml.in/yaml/v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// The Internal TLS page keeps its settings as a kustomization over the generated manifest, which
// patches objects by name and by position. Kustomize refuses a patch naming an object the manifest
// lacks, but builds two kinds of lost target without complaint: a target-selected patch that
// matches nothing does nothing, and a strategic merge into a renamed container adds a second
// container with no image. So the page's own blocks are built here against every Kubernetes golden,
// and the result is checked for what each patch sets out to do, and for the settings, mounts and
// ports the patches add fitting together. A manifest change that leaves a patch with nothing to
// patch fails here, not on an operator's cluster (#686 section 10).
const (
	internalTLSPage    = "../../../site/src/content/docs/deploy/kubernetes/internal-tls.mdx"
	internalTLSConsole = "## Admin console to auth server"
	internalTLSGateway = "## Gateway to auth server"
)

// The auth server's HTTP port, which the manifest writes, and the HTTPS port the page adds.
const (
	authServerHTTPPort   = 9090
	internalTLSHTTPSPort = 9443
)

// internalTLSGuide is what the page has an operator save beside goiabada-k8s.yaml. files are the
// first section's, by the name it saves each under, and omitFinalPatch says the section has the
// kustomization's final patch left out of a manifest without NetworkPolicies. The second section
// saves gatewayFiles, adds gatewayResources to the kustomization's resources and gatewayPatches to
// its patches.
type internalTLSGuide struct {
	files            map[string]string
	omitFinalPatch   bool
	gatewayFiles     map[string]string
	gatewayResources []string
	gatewayPatches   []any
}

var (
	// yamlBlock is a fenced YAML block, indented as a step's content is, with any title or other
	// metadata after the language.
	yamlBlock = regexp.MustCompile("(?m)^( *)```yaml(?:[ \t][^\n]*)?\n((?:.*\n)*?) *```$")
	// savedAs names the file a block is saved as, in the text before the block.
	savedAs = regexp.MustCompile("as `([^`]+\\.yaml)`")
	// addedToResources names a file the text adds to the kustomization's resources.
	addedToResources = regexp.MustCompile("Add `([^`]+\\.yaml)` to `resources`")
)

const (
	addedToPatches = "Add this entry to `patches`"
	omitFinalPatch = "Omit the final patch if you generated no NetworkPolicies."
)

// readInternalTLSGuide reads the files the page's two sections save, and what the second adds to
// the kustomization. Every YAML block is either saved under a name or added to the patches, so a
// block the page adds some other way fails here until this test knows what to do with it.
func readInternalTLSGuide(page string) (internalTLSGuide, error) {
	guide := internalTLSGuide{}
	console, found := docsreader.SectionText(page, internalTLSConsole)
	if !found {
		return guide, fmt.Errorf("no %q section", internalTLSConsole)
	}
	gateway, found := docsreader.SectionText(page, internalTLSGateway)
	if !found {
		return guide, fmt.Errorf("no %q section", internalTLSGateway)
	}
	var patches []string
	var err error
	if guide.files, patches, err = savedBlocks(console); err != nil {
		return guide, fmt.Errorf("%s: %w", internalTLSConsole, err)
	}
	if len(patches) > 0 {
		return guide, fmt.Errorf("%s adds to the patches before saving kustomization.yaml", internalTLSConsole)
	}
	guide.omitFinalPatch = strings.Contains(console, omitFinalPatch)
	if guide.gatewayFiles, patches, err = savedBlocks(gateway); err != nil {
		return guide, fmt.Errorf("%s: %w", internalTLSGateway, err)
	}
	for _, block := range patches {
		var entries []any
		if err := yaml.Unmarshal([]byte(block), &entries); err != nil {
			return guide, fmt.Errorf("%s: an entry added to the patches is not a YAML list: %w", internalTLSGateway, err)
		}
		guide.gatewayPatches = append(guide.gatewayPatches, entries...)
	}
	for _, m := range addedToResources.FindAllStringSubmatch(gateway, -1) {
		guide.gatewayResources = append(guide.gatewayResources, m[1])
	}
	if _, ok := guide.files["kustomization.yaml"]; !ok {
		return guide, fmt.Errorf("%s saves no kustomization.yaml", internalTLSConsole)
	}
	return guide, nil
}

// savedBlocks reads a section's YAML blocks, by the name the text before each saves it as, and the
// blocks it adds to the kustomization's patches.
func savedBlocks(section string) (files map[string]string, patches []string, err error) {
	files = map[string]string{}
	previous := 0
	for _, m := range yamlBlock.FindAllStringSubmatchIndex(section, -1) {
		before := section[previous:m[0]]
		previous = m[1]
		block := dedent(section[m[4]:m[5]], section[m[2]:m[3]])
		names := savedAs.FindAllStringSubmatch(before, -1)
		switch {
		case strings.Contains(before, addedToPatches):
			patches = append(patches, block)
		case len(names) > 0:
			name := names[len(names)-1][1]
			if _, twice := files[name]; twice {
				return nil, nil, fmt.Errorf("saves %s twice", name)
			}
			files[name] = block
		default:
			return nil, nil, fmt.Errorf("a YAML block is neither saved as a file nor added to the patches:\n%s", block)
		}
	}
	return files, patches, nil
}

// dedent removes a step's indentation from each line of its block.
func dedent(block, indent string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(block, "\n") {
		out.WriteString(strings.TrimPrefix(line, indent))
	}
	return out.String()
}

// buildInternalTLS builds the page's kustomization over the manifest, as an operator who follows
// the first section, or both, would have it: without the final patch when the manifest has no
// NetworkPolicy, where the page says to leave it out.
func buildInternalTLS(manifest string, guide internalTLSGuide, gateway bool) (string, error) {
	files := maps.Clone(guide.files)
	files["goiabada-k8s.yaml"] = manifest
	var kustomization map[string]any
	if err := yaml.Unmarshal([]byte(files["kustomization.yaml"]), &kustomization); err != nil {
		return "", fmt.Errorf("kustomization.yaml: %w", err)
	}
	patches, _ := kustomization["patches"].([]any)
	if len(patches) == 0 {
		return "", errors.New("kustomization.yaml has no patches")
	}
	manifestObjects, err := decodeObjects(manifest)
	if err != nil {
		return "", err
	}
	if guide.omitFinalPatch && !slices.ContainsFunc(manifestObjects, func(o object) bool { return o.kind == "NetworkPolicy" }) {
		last, _ := patches[len(patches)-1].(map[string]any)
		if target, _ := last["target"].(map[string]any); target["kind"] != "NetworkPolicy" {
			return "", fmt.Errorf("the page says %q, but the final patch is %v", omitFinalPatch, last)
		}
		patches = patches[:len(patches)-1]
	}
	if gateway {
		maps.Copy(files, guide.gatewayFiles)
		resources, _ := kustomization["resources"].([]any)
		for _, r := range guide.gatewayResources {
			resources = append(resources, r)
		}
		kustomization["resources"] = resources
		patches = append(slices.Clip(patches), guide.gatewayPatches...)
	}
	kustomization["patches"] = patches
	content, err := yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	files["kustomization.yaml"] = string(content)

	fs := filesys.MakeFsInMemory()
	for name, file := range files {
		if err = fs.WriteFile("/goiabada/"+name, []byte(file)); err != nil {
			return "", err
		}
	}
	built, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(fs, "/goiabada")
	if err != nil {
		return "", fmt.Errorf("kustomize refuses the kustomization: %w", err)
	}
	content, err = built.AsYaml()
	return string(content), err
}

// object is one decoded document of a YAML stream, with its kind and name.
type object struct {
	kind, name string
	doc        map[string]any
}

func (o object) String() string { return o.kind + " " + o.name }

func decodeObjects(content string) ([]object, error) {
	var objects []object
	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return objects, nil
		}
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		metadata, _ := doc["metadata"].(map[string]any)
		kind, _ := doc["kind"].(string)
		name, _ := metadata["name"].(string)
		objects = append(objects, object{kind, name, doc})
	}
}

func objectNamed(objects []object, kind, name string) (object, bool) {
	i := slices.IndexFunc(objects, func(o object) bool { return o.kind == kind && o.name == name })
	if i < 0 {
		return object{}, false
	}
	return objects[i], true
}

// internalTLSFindings builds the page's kustomization over the manifest and says what in the
// result differs from what the page sets out to do.
func internalTLSFindings(manifest string, guide internalTLSGuide, gateway bool) ([]string, error) {
	built, err := buildInternalTLS(manifest, guide, gateway)
	if err != nil {
		return nil, err
	}
	base, err := decodeObjects(manifest)
	if err != nil {
		return nil, err
	}
	result, err := decodeObjects(built)
	if err != nil {
		return nil, err
	}
	added := []string{}
	if gateway {
		added = guide.gatewayResources
	}
	var findings []string
	findings = append(findings, objectFindings(base, result, guide, added)...)
	findings = append(findings, mergeFindings(base, result, guide)...)
	findings = append(findings, wiringFindings(result)...)
	findings = append(findings, networkPolicyFindings(result)...)
	findings = append(findings, routeFindings(result, gateway)...)
	findings = append(findings, httpsFindings(result, gateway)...)
	if gateway {
		findings = append(findings, backendTLSFindings(result)...)
	}
	return findings, nil
}

// objectFindings: the build holds the manifest's objects and those of the resources the page adds,
// and nothing else, and every object the patches name is one the manifest writes.
func objectFindings(base, result []object, guide internalTLSGuide, added []string) []string {
	var findings []string
	want := slices.Clone(base)
	for _, name := range added {
		objects, err := decodeObjects(guide.gatewayFiles[name])
		if err != nil || len(objects) == 0 {
			findings = append(findings, fmt.Sprintf("%s, added to the resources, holds no object the page saves", name))
		}
		want = append(want, objects...)
	}
	for _, o := range want {
		if _, ok := objectNamed(result, o.kind, o.name); !ok {
			findings = append(findings, fmt.Sprintf("the build has no %s", o))
		}
	}
	for _, o := range result {
		if _, ok := objectNamed(want, o.kind, o.name); !ok {
			findings = append(findings, fmt.Sprintf("the build adds %s, which neither the manifest nor the page writes", o))
		}
	}
	return findings
}

// mergeFindings: every value the patch files set is in the object it patches, and each merge
// joined what the manifest already had. A container patch that names no container the manifest
// writes adds one with no image; a Service port patch that matches no port adds one beside it.
func mergeFindings(base, result []object, guide internalTLSGuide) []string {
	var findings []string
	for _, name := range strategicMergeFiles(guide.files["kustomization.yaml"]) {
		patches, err := decodeObjects(guide.files[name])
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		for _, patch := range patches {
			o, ok := objectNamed(result, patch.kind, patch.name)
			if !ok {
				continue // objectFindings says so, or the build refused it
			}
			for _, missing := range uncovered(patch.doc, o.doc, "") {
				findings = append(findings, fmt.Sprintf("%s: %s sets %s, which the build lacks", name, patch, missing))
			}
		}
	}
	for _, o := range base {
		r, _ := objectNamed(result, o.kind, o.name)
		switch o.kind {
		case "Deployment":
			if before, after := containerNames(o.doc), containerNames(r.doc); !slices.Equal(before, after) {
				findings = append(findings, fmt.Sprintf("%s runs containers %v after the patches, %v before", o, after, before))
			}
		case "Service":
			findings = append(findings, servicePortFindings(o, r)...)
		}
	}
	return findings
}

// strategicMergeFiles are the files the kustomization's patches name by path.
func strategicMergeFiles(kustomization string) []string {
	var k struct {
		Patches []struct {
			Path string `yaml:"path"`
		} `yaml:"patches"`
	}
	if yaml.Unmarshal([]byte(kustomization), &k) != nil {
		return nil
	}
	var names []string
	for _, p := range k.Patches {
		if p.Path != "" {
			names = append(names, p.Path)
		}
	}
	return names
}

// uncovered are the paths of the values in want that got lacks. A list item in want is covered by
// any item of got's list that covers it.
func uncovered(want, got any, path string) []string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{path}
		}
		var missing []string
		for _, key := range slices.Sorted(maps.Keys(w)) {
			missing = append(missing, uncovered(w[key], g[key], path+"/"+key)...)
		}
		return missing
	case []any:
		g, _ := got.([]any)
		var missing []string
		for i, item := range w {
			if !slices.ContainsFunc(g, func(candidate any) bool { return len(uncovered(item, candidate, "")) == 0 }) {
				missing = append(missing, fmt.Sprintf("%s/%d", path, i))
			}
		}
		return missing
	default:
		if !reflect.DeepEqual(want, got) {
			return []string{path}
		}
		return nil
	}
}

func containerNames(deployment map[string]any) []string {
	var names []string
	for _, c := range listAt(deployment, "spec", "template", "spec", "containers") {
		container, _ := c.(map[string]any)
		name, _ := container["name"].(string)
		names = append(names, name)
	}
	return names
}

// servicePortFindings: the Service still has the manifest's ports, and with more than one, each has
// a name of its own, as the API server requires.
func servicePortFindings(base, result object) []string {
	var findings []string
	ports := listAt(result.doc, "spec", "ports")
	numbers, names := map[any]bool{}, map[any]bool{}
	for _, p := range ports {
		port, _ := p.(map[string]any)
		numbers[port["port"]] = true
		if len(ports) > 1 {
			if name, _ := port["name"].(string); name == "" || names[name] {
				findings = append(findings, fmt.Sprintf("%s has %d ports, and port %v has no name of its own", result, len(ports), port["port"]))
			}
			names[port["name"]] = true
		}
	}
	for _, p := range listAt(base.doc, "spec", "ports") {
		port, _ := p.(map[string]any)
		if !numbers[port["port"]] {
			findings = append(findings, fmt.Sprintf("%s lost its port %v", result, port["port"]))
		}
	}
	return findings
}

// wiringFindings: in each Deployment's pod, every file named by a ConfigMap a container reads is
// one of that container's mounts or lies under one, every mount names a volume of the pod, and
// every listener port the ConfigMap sets is a port number the container declares. Each Service
// sends to a port its pods declare. A mount moved, renamed or put into the other container breaks
// one of these. The values checked are the ConfigMaps', so a container that overrides one in env:,
// or reads a ConfigMap under a prefix, is a finding rather than a value worked out.
func wiringFindings(result []object) []string {
	var findings []string
	for _, o := range result {
		if o.kind != "Deployment" {
			continue
		}
		pod := atPath(o.doc, "spec", "template", "spec")
		volumes := map[any]bool{}
		for _, v := range listAt(pod, "volumes") {
			volume, _ := v.(map[string]any)
			volumes[volume["name"]] = true
		}
		for _, c := range listAt(pod, "containers") {
			container, _ := c.(map[string]any)
			var mounts []string
			for _, m := range listAt(container, "volumeMounts") {
				mount, _ := m.(map[string]any)
				path, _ := mount["mountPath"].(string)
				mounts = append(mounts, strings.TrimSuffix(path, "/"))
				if !volumes[mount["name"]] {
					findings = append(findings, fmt.Sprintf("%s: container %v mounts volume %v, which the pod lacks", o, container["name"], mount["name"]))
				}
			}
			set := map[any]bool{}
			for _, e := range listAt(container, "env") {
				variable, _ := e.(map[string]any)
				set[variable["name"]] = true
			}
			for _, e := range listAt(container, "envFrom") {
				name, _ := atPath(e, "configMapRef", "name").(string)
				config, ok := objectNamed(result, "ConfigMap", name)
				if !ok {
					continue
				}
				if prefix, _ := atPath(e, "prefix").(string); prefix != "" {
					findings = append(findings, fmt.Sprintf("%s: container %v reads %s with prefix %q, which this test does not work out", o, container["name"], config, prefix))
				}
				data, _ := config.doc["data"].(map[string]any)
				for _, key := range slices.Sorted(maps.Keys(data)) {
					value, _ := data[key].(string)
					mounted := slices.ContainsFunc(mounts, func(m string) bool { return value == m || strings.HasPrefix(value, m+"/") })
					switch {
					case set[key]:
						findings = append(findings, fmt.Sprintf("%s: container %v sets %s in env:, over the value from %s that this test checks", o, container["name"], key, config))
					case strings.HasPrefix(value, "/") && !mounted:
						findings = append(findings, fmt.Sprintf("%s: container %v reads %s %s from %s, and none of its mounts holds it", o, container["name"], key, value, config))
					case strings.Contains(key, "_LISTEN_PORT_") && !declaresPortNumber(container, value):
						findings = append(findings, fmt.Sprintf("%s: container %v listens on %s %s from %s, a port number it does not declare", o, container["name"], key, value, config))
					}
				}
			}
		}
	}
	for _, o := range result {
		if o.kind != "Service" {
			continue
		}
		selector, _ := atPath(o.doc, "spec", "selector").(map[string]any)
		for _, p := range listAt(o.doc, "spec", "ports") {
			port, _ := p.(map[string]any)
			declared := slices.ContainsFunc(result, func(d object) bool {
				if d.kind != "Deployment" || !labelsMatch(selector, podLabels(d.doc)) {
					return false
				}
				return slices.ContainsFunc(listAt(d.doc, "spec", "template", "spec", "containers"), func(c any) bool {
					container, _ := c.(map[string]any)
					return declaresPort(container, fmt.Sprint(port["targetPort"]))
				})
			})
			if !declared {
				findings = append(findings, fmt.Sprintf("%s sends port %v to %v, which no container it selects declares", o, port["port"], port["targetPort"]))
			}
		}
	}
	return findings
}

// declaresPort says whether the container declares the port, by number or by name, as a Service's
// targetPort may name it.
func declaresPort(container map[string]any, port string) bool {
	return declaresPortNumber(container, port) || slices.ContainsFunc(listAt(container, "ports"), func(p any) bool {
		declared, _ := p.(map[string]any)
		return declared["name"] == port
	})
}

// declaresPortNumber says whether the container declares the port by number, the only form a
// server's listener setting takes.
func declaresPortNumber(container map[string]any, port string) bool {
	return slices.ContainsFunc(listAt(container, "ports"), func(p any) bool {
		declared, _ := p.(map[string]any)
		return fmt.Sprint(declared["containerPort"]) == port
	})
}

func podLabels(deployment map[string]any) map[string]any {
	labels, _ := atPath(deployment, "spec", "template", "metadata", "labels").(map[string]any)
	return labels
}

// labelsMatch says whether every label the selector names has its value in labels.
func labelsMatch(selector, labels map[string]any) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

// networkPolicyFindings: a NetworkPolicy selecting the auth server's pods, by the labels its
// Deployment gives them, admits the HTTPS port from exactly where it admits the HTTP port. In a
// build with NetworkPolicies of which none selects those pods, the page's patch reached none.
func networkPolicyFindings(result []object) []string {
	var findings []string
	authServer, _ := objectNamed(result, "Deployment", "goiabada-authserver")
	labels := podLabels(authServer.doc)
	policies, selecting := 0, 0
	for _, o := range result {
		if o.kind != "NetworkPolicy" {
			continue
		}
		policies++
		selector, _ := atPath(o.doc, "spec", "podSelector").(map[string]any)
		if _, ok := selector["matchExpressions"]; ok {
			findings = append(findings, fmt.Sprintf("%s selects pods by expression, which this test does not read", o))
			continue
		}
		matchLabels, _ := selector["matchLabels"].(map[string]any)
		if !labelsMatch(matchLabels, labels) {
			continue
		}
		selecting++
		for i, r := range listAt(o.doc, "spec", "ingress") {
			rule, _ := r.(map[string]any)
			switch http, https := admitsPort(rule, authServerHTTPPort), admitsPort(rule, internalTLSHTTPSPort); {
			case http && !https:
				findings = append(findings, fmt.Sprintf("%s: ingress rule %d admits port %d but not %d", o, i, authServerHTTPPort, internalTLSHTTPSPort))
			case https && !http:
				findings = append(findings, fmt.Sprintf("%s: ingress rule %d admits port %d but not %d", o, i, internalTLSHTTPSPort, authServerHTTPPort))
			}
		}
	}
	if policies > 0 && selecting == 0 {
		findings = append(findings, "the build has NetworkPolicies, and none selects the auth server's pods")
	}
	return findings
}

// admitsPort says whether the rule admits TCP on the port. A rule naming no ports admits every
// port, and a port naming no protocol is TCP.
func admitsPort(rule map[string]any, number int) bool {
	ports, _ := rule["ports"].([]any)
	if len(ports) == 0 {
		return true
	}
	return slices.ContainsFunc(ports, func(p any) bool {
		port, _ := p.(map[string]any)
		protocol, _ := port["protocol"].(string)
		return port["port"] == number && (protocol == "" || protocol == "TCP")
	})
}

// routeFindings: every route to the auth server's Service sends to the HTTP port until the second
// section, and to the HTTPS port after it.
func routeFindings(result []object, gateway bool) []string {
	want := authServerHTTPPort
	if gateway {
		want = internalTLSHTTPSPort
	}
	var findings []string
	routed := false
	for _, o := range result {
		if o.kind != "HTTPRoute" {
			continue
		}
		for _, r := range listAt(o.doc, "spec", "rules") {
			rule, _ := r.(map[string]any)
			refs, _ := rule["backendRefs"].([]any)
			for _, b := range refs {
				ref, _ := b.(map[string]any)
				if ref["name"] != "goiabada-authserver" {
					continue
				}
				routed = true
				if ref["port"] != want {
					findings = append(findings, fmt.Sprintf("%s sends the auth server's traffic to port %v, want %d", o, ref["port"], want))
				}
			}
		}
	}
	if !routed {
		findings = append(findings, "no HTTPRoute sends to the auth server's Service")
	}
	return findings
}

// httpsFindings follows the HTTPS hop the page sets up: the auth server listens for HTTPS on the
// page's port, the Service's port of that number sends to that listener, and after the second
// section the BackendTLSPolicy covers that Service port. A targetPort or sectionName left on the
// HTTP port would pass every check above, since that port exists too.
func httpsFindings(result []object, gateway bool) []string {
	var findings []string
	want := fmt.Sprint(internalTLSHTTPSPort)
	authServer, _ := objectNamed(result, "Deployment", "goiabada-authserver")
	listener := ""
	for _, c := range listAt(authServer.doc, "spec", "template", "spec", "containers") {
		for _, e := range listAt(c, "envFrom") {
			name, _ := atPath(e, "configMapRef", "name").(string)
			if config, ok := objectNamed(result, "ConfigMap", name); ok {
				if value, ok := atPath(config.doc, "data", "GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS").(string); ok {
					listener = value
				}
			}
		}
	}
	if listener != want {
		findings = append(findings, fmt.Sprintf("the auth server listens for HTTPS on %q, want %q", listener, want))
	}
	service, _ := objectNamed(result, "Service", "goiabada-authserver")
	i := slices.IndexFunc(listAt(service.doc, "spec", "ports"), func(p any) bool {
		port, _ := p.(map[string]any)
		return port["port"] == internalTLSHTTPSPort
	})
	if i < 0 {
		return append(findings, fmt.Sprintf("Service goiabada-authserver has no port %d", internalTLSHTTPSPort))
	}
	https, _ := listAt(service.doc, "spec", "ports")[i].(map[string]any)
	target := fmt.Sprint(https["targetPort"])
	if !slices.ContainsFunc(listAt(authServer.doc, "spec", "template", "spec", "containers"), func(c any) bool {
		container, _ := c.(map[string]any)
		return slices.ContainsFunc(listAt(container, "ports"), func(p any) bool {
			declared, _ := p.(map[string]any)
			return fmt.Sprint(declared["containerPort"]) == want && (target == want || declared["name"] == target)
		})
	}) {
		findings = append(findings, fmt.Sprintf("Service goiabada-authserver sends port %d to %s, not to the HTTPS listener on %s", internalTLSHTTPSPort, target, want))
	}
	if !gateway {
		return findings
	}
	for _, o := range result {
		if o.kind != "BackendTLSPolicy" {
			continue
		}
		for _, t := range listAt(o.doc, "spec", "targetRefs") {
			ref, _ := t.(map[string]any)
			if ref["name"] == "goiabada-authserver" && ref["sectionName"] != https["name"] {
				findings = append(findings, fmt.Sprintf("%s covers Service port %v, not the HTTPS port %v the route sends to", o, ref["sectionName"], https["name"]))
			}
		}
	}
	return findings
}

// backendTLSFindings: a BackendTLSPolicy targets the auth server's Service, and each targets a
// Service port the build names.
func backendTLSFindings(result []object) []string {
	var findings []string
	protected := false
	for _, o := range result {
		if o.kind != "BackendTLSPolicy" {
			continue
		}
		for _, t := range listAt(o.doc, "spec", "targetRefs") {
			ref, _ := t.(map[string]any)
			name, _ := ref["name"].(string)
			service, ok := objectNamed(result, "Service", name)
			if !ok {
				findings = append(findings, fmt.Sprintf("%s targets Service %s, which the build lacks", o, name))
				continue
			}
			if !slices.ContainsFunc(listAt(service.doc, "spec", "ports"), func(p any) bool {
				port, _ := p.(map[string]any)
				return port["name"] == ref["sectionName"]
			}) {
				findings = append(findings, fmt.Sprintf("%s targets port %v of %s, which has no port by that name", o, ref["sectionName"], service))
				continue
			}
			protected = protected || name == "goiabada-authserver"
		}
	}
	if !protected {
		findings = append(findings, "no BackendTLSPolicy targets the auth server's Service, which the route sends to on its HTTPS port")
	}
	return findings
}

// atPath walks a decoded document by keys, nil where one is missing.
func atPath(node any, keys ...string) any {
	for _, key := range keys {
		m, _ := node.(map[string]any)
		node = m[key]
	}
	return node
}

func listAt(node any, keys ...string) []any {
	list, _ := atPath(node, keys...).([]any)
	return list
}

func readInternalTLSPage(t *testing.T) internalTLSGuide {
	t.Helper()
	page, err := os.ReadFile(internalTLSPage)
	if err != nil {
		t.Fatalf("unable to read the Internal TLS page: %v", err)
	}
	guide, err := readInternalTLSGuide(string(page))
	if err != nil {
		t.Fatalf("%s: %v", internalTLSPage, err)
	}
	return guide
}

func TestInternalTLSDocs_TheKustomizationPatchesEveryGeneratedManifest(t *testing.T) {
	guide := readInternalTLSPage(t)
	withNetworkPolicy := 0
	for _, c := range goldenCases() {
		if c.deployment != deploymentKubernetes {
			continue
		}
		manifest := descriptionOf(c.config())
		if strings.Contains(manifest, "\nkind: NetworkPolicy\n") {
			withNetworkPolicy++
		}
		for _, gateway := range []bool{false, true} {
			stage := internalTLSConsole
			if gateway {
				stage = internalTLSGateway
			}
			findings, err := internalTLSFindings(manifest, guide, gateway)
			if err != nil {
				t.Errorf("%s, through %q: %v", c.name, stage, err)
			}
			for _, finding := range findings {
				t.Errorf("%s, through %q: %s", c.name, stage, finding)
			}
		}
	}
	if withNetworkPolicy == 0 {
		t.Error("no Kubernetes golden has a NetworkPolicy, so the page's NetworkPolicy patch went unbuilt")
	}
}

// changedManifest is the golden case's manifest with change made to its decoded objects.
func changedManifest(t *testing.T, name string, change func(objects []object)) string {
	t.Helper()
	i := slices.IndexFunc(goldenCases(), func(c goldenCase) bool { return c.name == name })
	if i < 0 {
		t.Fatalf("no golden case is named %s", name)
	}
	objects, err := decodeObjects(descriptionOf(goldenCases()[i].config()))
	if err != nil {
		t.Fatal(err)
	}
	change(objects)
	var out strings.Builder
	for _, o := range objects {
		content, err := yaml.Marshal(o.doc)
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString("---\n")
		out.Write(content)
	}
	return out.String()
}

func objectToChange(t *testing.T, objects []object, kind, name string) map[string]any {
	t.Helper()
	o, ok := objectNamed(objects, kind, name)
	if !ok {
		t.Fatalf("the manifest has no %s %s", kind, name)
	}
	return o.doc
}

// Each change below is one a later section of #686 could make to the manifest. Kustomize builds
// every one of them, so each must be a finding.
func TestInternalTLSFindings_FindWhatAManifestChangeLeftUnpatched(t *testing.T) {
	guide := readInternalTLSPage(t)
	tests := []struct {
		name   string
		golden string
		change func(t *testing.T, objects []object)
		want   string
	}{
		{"a renamed container", "kubernetes-postgres", func(t *testing.T, objects []object) {
			deployment := objectToChange(t, objects, "Deployment", "goiabada-authserver")
			listAt(deployment, "spec", "template", "spec", "containers")[0].(map[string]any)["name"] = "goiabada-authserver"
		}, "runs containers"},
		{"a renamed NetworkPolicy", "kubernetes-network-policy-postgres", func(t *testing.T, objects []object) {
			objectToChange(t, objects, "NetworkPolicy", "goiabada-authserver")["metadata"].(map[string]any)["name"] = "goiabada-authserver-ingress"
		}, "ingress rule 0 admits port 9090 but not 9443"},
		{"the metrics rule first", "kubernetes-metrics-network-policy-postgres", func(t *testing.T, objects []object) {
			policy := objectToChange(t, objects, "NetworkPolicy", "goiabada-authserver")
			rules := listAt(policy, "spec", "ingress")
			rules[0], rules[1] = rules[1], rules[0]
		}, "ingress rule 0 admits port 9443 but not 9090"},
		{"a renamed HTTPRoute", "kubernetes-postgres", func(t *testing.T, objects []object) {
			objectToChange(t, objects, "HTTPRoute", "goiabada-authserver")["metadata"].(map[string]any)["name"] = "goiabada-auth"
		}, "to port 9090, want 9443"},
		{"another Service port", "kubernetes-postgres", func(t *testing.T, objects []object) {
			service := objectToChange(t, objects, "Service", "goiabada-authserver")
			listAt(service, "spec", "ports")[0].(map[string]any)["port"] = 8080
		}, "port 8080 has no name of its own"},
		{"relabelled pods with the metrics rule first", "kubernetes-metrics-network-policy-postgres", func(t *testing.T, objects []object) {
			for _, o := range objects {
				relabel(o.doc)
			}
			policy := objectToChange(t, objects, "NetworkPolicy", "goiabada-authserver")
			rules := listAt(policy, "spec", "ingress")
			rules[0], rules[1] = rules[1], rules[0]
		}, "ingress rule 0 admits port 9443 but not 9090"},
		{"its ConfigMap read under a prefix", "kubernetes-postgres", func(t *testing.T, objects []object) {
			deployment := objectToChange(t, objects, "Deployment", "goiabada-authserver")
			container := listAt(deployment, "spec", "template", "spec", "containers")[0]
			listAt(container, "envFrom")[0].(map[string]any)["prefix"] = "TLS_"
		}, `with prefix "TLS_"`},
		{"a NetworkPolicy selecting other pods", "kubernetes-network-policy-postgres", func(t *testing.T, objects []object) {
			policy := objectToChange(t, objects, "NetworkPolicy", "goiabada-authserver")
			atPath(policy, "spec", "podSelector", "matchLabels").(map[string]any)["app"] = "goiabada-auth"
		}, "none selects the auth server's pods"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := changedManifest(t, tt.golden, func(objects []object) { tt.change(t, objects) })
			findings, err := internalTLSFindings(manifest, guide, true)
			if err != nil {
				t.Fatalf("the kustomization does not build, so this change needs no finding: %v", err)
			}
			if !slices.ContainsFunc(findings, func(f string) bool { return strings.Contains(f, tt.want) }) {
				t.Errorf("no finding says %q; findings: %q", tt.want, findings)
			}
		})
	}
}

// relabel moves every app label to app.kubernetes.io/name, selectors included, as a change to the
// standard labels could.
func relabel(node any) {
	switch n := node.(type) {
	case map[string]any:
		if value, ok := n["app"]; ok {
			delete(n, "app")
			n["app.kubernetes.io/name"] = value
		}
		for _, value := range n {
			relabel(value)
		}
	case []any:
		for _, value := range n {
			relabel(value)
		}
	}
}

// changedGuide is the guide with from replaced by to in one of the files either section saves,
// which must hold it once.
func changedGuide(t *testing.T, guide internalTLSGuide, file, from, to string) internalTLSGuide {
	t.Helper()
	changed := guide
	changed.files, changed.gatewayFiles = maps.Clone(guide.files), maps.Clone(guide.gatewayFiles)
	files := changed.files
	if _, ok := files[file]; !ok {
		files = changed.gatewayFiles
	}
	if strings.Count(files[file], from) != 1 {
		t.Fatalf("%s does not hold %q exactly once", file, from)
	}
	files[file] = strings.Replace(files[file], from, to, 1)
	return changed
}

// Each change below is a slip an edit to the page could make, leaving the patches applying to the
// manifest but the settings they make not working together. Kustomize builds every one of them,
// so each must be a finding.
func TestInternalTLSFindings_FindWhatAPageChangeBroke(t *testing.T) {
	guide := readInternalTLSPage(t)
	tests := []struct {
		name   string
		golden string
		change func(t *testing.T) internalTLSGuide
		want   string
	}{
		{"the certificate's mount moved", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", "mountPath: /etc/goiabada/internal-tls\n", "mountPath: /etc/goiabada/tls\n")
		}, "reads GOIABADA_AUTHSERVER_CERTFILE /etc/goiabada/internal-tls/tls.crt from ConfigMap goiabada-authserver-config, and none of its mounts holds it"},
		{"the CA read from the auth server's mount", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", `"/etc/goiabada/internal-ca/ca.crt"`, `"/etc/goiabada/internal-tls/ca.crt"`)
		}, "container adminconsole reads GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE"},
		{"a mount naming no volume", "kubernetes-verify-full-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", "- name: internal-tls\n          mountPath:", "- name: internal-tls-cert\n          mountPath:")
		}, "mounts volume internal-tls-cert, which the pod lacks"},
		{"the listener on another port", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS: "9443"`, `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS: "9444"`)
		}, "listens on GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS 9444"},
		{"the NetworkPolicy port over UDP", "kubernetes-network-policy-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "kustomization.yaml", "protocol: TCP", "protocol: UDP")
		}, "ingress rule 0 admits port 9090 but not 9443"},
		{"the listener named, not numbered", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS: "9443"`, `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS: "https"`)
		}, "a port number it does not declare"},
		{"the HTTPS Service port sent to the HTTP listener", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", "targetPort: 9443", "targetPort: 9090")
		}, "sends port 9443 to 9090, not to the HTTPS listener"},
		{"the BackendTLSPolicy on the HTTP port", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "backend-tls.yaml", "sectionName: https", "sectionName: http")
		}, "covers Service port http, not the HTTPS port https"},
		{"a certificate path set again in env:", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			return changedGuide(t, guide, "internal-tls-patches.yaml", "      - name: authserver\n        ports:",
				"      - name: authserver\n        env:\n        - name: GOIABADA_AUTHSERVER_CERTFILE\n          value: /tmp/missing.crt\n        ports:")
		}, "sets GOIABADA_AUTHSERVER_CERTFILE in env:"},
		{"the BackendTLSPolicy left out of the resources", "kubernetes-postgres", func(t *testing.T) internalTLSGuide {
			changed := guide
			changed.gatewayResources = nil
			return changed
		}, "no BackendTLSPolicy targets the auth server's Service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := slices.IndexFunc(goldenCases(), func(c goldenCase) bool { return c.name == tt.golden })
			if i < 0 {
				t.Fatalf("no golden case is named %s", tt.golden)
			}
			findings, err := internalTLSFindings(descriptionOf(goldenCases()[i].config()), tt.change(t), true)
			if err != nil {
				t.Fatalf("the kustomization does not build, so this change needs no finding: %v", err)
			}
			if !slices.ContainsFunc(findings, func(f string) bool { return strings.Contains(f, tt.want) }) {
				t.Errorf("no finding says %q; findings: %q", tt.want, findings)
			}
		})
	}
}

// A file mounted on its own, at the path its setting names, is held by its mount.
func TestInternalTLSFindings_AcceptAFileMountedOnItsOwn(t *testing.T) {
	guide := changedGuide(t, readInternalTLSPage(t), "internal-tls-patches.yaml",
		"        - name: internal-tls\n          mountPath: /etc/goiabada/internal-tls\n",
		"        - name: internal-tls\n          mountPath: /etc/goiabada/internal-tls/tls.crt\n          subPath: tls.crt\n"+
			"        - name: internal-tls\n          mountPath: /etc/goiabada/internal-tls/tls.key\n          subPath: tls.key\n")
	findings, err := internalTLSFindings(descriptionOf(goldenConfig(deploymentKubernetes, "postgres")), guide, true)
	if err != nil || len(findings) > 0 {
		t.Errorf("err %v, findings %q", err, findings)
	}
}

// A patch whose target the manifest stopped writing is refused by kustomize itself.
func TestInternalTLSFindings_ARenamedConfigMapStopsTheBuild(t *testing.T) {
	guide := readInternalTLSPage(t)
	manifest := changedManifest(t, "kubernetes-postgres", func(objects []object) {
		objectToChange(t, objects, "ConfigMap", "goiabada-adminconsole-config")["metadata"].(map[string]any)["name"] = "goiabada-adminconsole-settings"
	})
	if _, err := internalTLSFindings(manifest, guide, false); err == nil {
		t.Error("the kustomization built with its ConfigMap patch's target renamed")
	}
}

// The page reads as its blocks are saved: a block saved under no name, or saved twice, stops the
// reader rather than being built as something else.
func TestInternalTLSGuide_ABlockWithNoPlaceStopsTheReader(t *testing.T) {
	block := "   ```yaml\n   kind: ConfigMap\n   ```\n"
	for name, section := range map[string]string{
		"unnamed":     "1. Use this:\n\n" + block,
		"saved twice": "1. Save this as `a.yaml`:\n\n" + block + "\n2. Save this as `a.yaml`:\n\n" + block,
	} {
		if _, _, err := savedBlocks(section); err == nil {
			t.Errorf("%s: the reader accepted %q", name, section)
		}
	}
	files, patches, err := savedBlocks("1. Save this as `kustomization.yaml`. Omit this:\n\n" + block + "\n2. " + addedToPatches + " in `kustomization.yaml`:\n\n" + block)
	if err != nil || files["kustomization.yaml"] != "kind: ConfigMap\n" || len(patches) != 1 {
		t.Errorf("files %q, patches %q, err %v", files, patches, err)
	}
}

// A titled fence is read as any other.
func TestInternalTLSGuide_ReadsATitledBlock(t *testing.T) {
	files, _, err := savedBlocks("1. Save this as `a.yaml`:\n\n   ```yaml title=\"a.yaml\"\n   kind: ConfigMap\n   ```\n")
	if err != nil || files["a.yaml"] != "kind: ConfigMap\n" {
		t.Errorf("files %q, err %v", files, err)
	}
}
