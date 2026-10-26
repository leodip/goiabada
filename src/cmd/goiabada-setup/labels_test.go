package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The prompts of the Labels and annotations step, none by default (#686 section 6).
const (
	labelsPrompt      = "Labels (e.g., team=identity,cost-center=1234), blank for none: "
	annotationsPrompt = "Annotations (e.g., example.com/owner=identity-team), blank for none: "
)

// withoutStandardLabels is labels without the app.kubernetes.io ones every object carries.
func withoutStandardLabels(labels map[string]any) map[string]any {
	own := map[string]any{}
	for key, value := range labels {
		if !strings.HasPrefix(key, standardLabelPrefix) {
			own[key] = value
		}
	}
	return own
}

// The operator's labels and annotations of labelsConfig, with a key YAML would read as a boolean
// unquoted and an annotation value holding spaces and a colon.
var (
	operatorLabels      = []keyValue{{"team", "identity"}, {"example.com/cost-center", "1234"}, {"yes", "no"}}
	operatorAnnotations = []keyValue{{"example.com/owner", "identity team: on call"}}
)

// Every object of every Kubernetes golden case, in both files, carries the standard labels, and,
// given labels and annotations, those too, as does each pod template, which a policy on Pods checks:
// the Namespace and the objects both servers share without a component, every other object with the
// component of the server it belongs to (#686 section 6).
func TestKubernetesManifest_EveryObjectCarriesTheLabels(t *testing.T) {
	checked := 0
	for _, tc := range goldenCases() {
		if tc.deployment != deploymentKubernetes {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config()
			config.Labels, config.Annotations = operatorLabels, operatorAnnotations
			for kind, byName := range kubernetesDocuments(t, config) {
				for name, doc := range byName {
					metadata := at[map[string]any](t, doc, "metadata")
					checkCarriesTheLabels(t, kind+" "+name, metadata, config, wantComponent(t, kind, name))
					if kind == "Deployment" {
						template := at[map[string]any](t, doc, "spec", "template", "metadata")
						checkCarriesTheLabels(t, "the pod template of "+name, template, config, wantComponent(t, kind, name))
						if got := at[string](t, template, "labels", "app"); got != name {
							t.Errorf("the pod template of %s is labeled app: %q", name, got)
						}
					}
					checked++
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("no Kubernetes object was checked")
	}
}

// objectComponents is the component each object belongs to, by name: the server it serves, the
// auth server for the Secrets and the ConfigMap only it reads, and none for what both servers
// share, the Namespace, the Gateway, the PodMonitor, the redirect route and goiabada-secrets.
var objectComponents = map[string]string{
	"goiabada-authserver":          "authserver",
	"goiabada-authserver-config":   "authserver",
	"goiabada-encryption-key":      "authserver",
	"goiabada-db-client-tls":       "authserver",
	"goiabada-db-ca":               "authserver",
	"goiabada-adminconsole":        "adminconsole",
	"goiabada-adminconsole-config": "adminconsole",
	"goiabada":                     "",
	"goiabada-secrets":             "",
	"goiabada-https-redirect":      "",
}

// wantComponent is the component of the object kind name, failing the test for an object the table
// doesn't know.
func wantComponent(t *testing.T, kind, name string) string {
	t.Helper()
	if kind == "Namespace" {
		return ""
	}
	component, known := objectComponents[name]
	if !known {
		t.Fatalf("no component is expected of %s %s", kind, name)
	}
	return component
}

func checkCarriesTheLabels(t *testing.T, what string, metadata map[string]any, config *Config, component string) {
	t.Helper()
	labels, _ := metadata["labels"].(map[string]any)
	want := map[string]any{
		"app.kubernetes.io/name":       "goiabada",
		"app.kubernetes.io/instance":   config.K8sNamespace,
		"app.kubernetes.io/part-of":    "goiabada",
		"app.kubernetes.io/version":    imageTag,
		"app.kubernetes.io/managed-by": "goiabada-setup",
	}
	if component != "" {
		want["app.kubernetes.io/component"] = component
	}
	for _, label := range config.Labels {
		want[label.key] = label.value
	}
	for key, value := range want {
		if labels[key] != value {
			t.Errorf("%s is labeled %s: %v, want %q", what, key, labels[key], value)
		}
	}
	if component == "" && labels["app.kubernetes.io/component"] != nil {
		t.Errorf("%s, which both servers share, is labeled component %v", what, labels["app.kubernetes.io/component"])
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	for _, annotation := range config.Annotations {
		if annotations[annotation.key] != annotation.value {
			t.Errorf("%s is annotated %s: %v, want %q", what, annotation.key, annotations[annotation.key], annotation.value)
		}
	}
}

// Every selector still matches app alone: a Deployment's selector cannot change once it exists, so
// one that matched the new labels would leave a deployment of an earlier release unable to apply.
func TestKubernetesManifest_SelectorsMatchAppAlone(t *testing.T) {
	config := kubernetesConfig()
	config.Labels = operatorLabels
	config.Metrics, config.NetworkPolicy, config.ProxyNamespace, config.MetricsNamespace = metricsPodMonitor, true, envoyProxyNamespace, "monitoring"
	docs := kubernetesDocuments(t, config)
	for _, w := range workloads {
		app := map[string]any{"app": w.deployment}
		for what, selector := range map[string]any{
			"the Deployment":        at[map[string]any](t, docs["Deployment"][w.deployment], "spec", "selector", "matchLabels"),
			"the Service":           at[map[string]any](t, docs["Service"][w.deployment], "spec", "selector"),
			"the disruption budget": at[map[string]any](t, docs["PodDisruptionBudget"][w.deployment], "spec", "selector", "matchLabels"),
			"the NetworkPolicy":     at[map[string]any](t, docs["NetworkPolicy"][w.deployment], "spec", "podSelector", "matchLabels"),
		} {
			if !reflect.DeepEqual(selector, app) {
				t.Errorf("%s of %s selects %v, want %v", what, w.deployment, selector, app)
			}
		}
	}
	monitor := at[[]any](t, docs["PodMonitor"]["goiabada"], "spec", "selector", "matchExpressions")
	if got := only[map[string]any](t, monitor, "the PodMonitor's selector")["key"]; got != "app" {
		t.Errorf("the PodMonitor selects by %v, want app", got)
	}
}

// An operator's key is quoted, so a key YAML reads as a boolean stays a string.
func TestKubernetesManifest_QuotesTheOperatorsKeys(t *testing.T) {
	config := kubernetesConfig()
	config.Labels, config.Annotations = operatorLabels, operatorAnnotations
	content := descriptionOf(config)
	for _, want := range []string{`    "yes": "no"`, `    "example.com/owner": "identity team: on call"`, `    app.kubernetes.io/name: "goiabada"`} {
		if !strings.Contains(content, want) {
			t.Errorf("the manifest has no line %q", want)
		}
	}
}

func TestParseLabelsAndAnnotations(t *testing.T) {
	for input, want := range map[string][]keyValue{
		"":                                   nil,
		"team=identity, example.com/cc=1234": {{"team", "identity"}, {"example.com/cc", "1234"}},
		"empty=":                             {{"empty", ""}},
	} {
		if got, err := parseLabels(input); err != nil || !slices.Equal(got, want) {
			t.Errorf("parseLabels(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	if got, err := parseAnnotations("example.com/owner=identity team: on call, note=a=b"); err != nil ||
		!slices.Equal(got, []keyValue{{"example.com/owner", "identity team: on call"}, {"note", "a=b"}}) {
		t.Errorf("parseAnnotations read %v, %v", got, err)
	}
	for input, why := range map[string]string{
		"team":                                 "not key=value",
		"team=a,team=b":                        "given twice",
		"app=x":                                "sets the label app itself",
		"app.kubernetes.io/name=x":             "sets the label app.kubernetes.io/name itself",
		"pod-security.kubernetes.io/warn=base": "sets the label pod-security.kubernetes.io/warn itself",
		"team=has space":                       "not a label value",
		"Example.com/team=x":                   "not a label key",
	} {
		if _, err := parseLabels(input); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("parseLabels(%q) returned %v, want it refused as %s", input, err, why)
		}
	}
	for input, why := range map[string]string{
		"goiabada.dev/config-checksum=x":   "sets the annotation goiabada.dev/config-checksum itself",
		"prometheus.io/scrape=true":        "sets the annotation prometheus.io/scrape itself",
		"cert-manager.io/cluster-issuer=x": "sets the annotation cert-manager.io/cluster-issuer itself",
		"bad key=x":                        "not an annotation key",
	} {
		if _, err := parseAnnotations(input); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("parseAnnotations(%q) returned %v, want it refused as %s", input, err, why)
		}
	}
}

// Kubernetes asks the labels and annotations, none by default, and asks again for labels the
// PodMonitor's own labels name; the flags answer without a prompt, and refuse that overlap too.
func TestWizard_AsksTheLabelsAndAnnotations(t *testing.T) {
	steps := metricsScript(t, "3", "release=prom", false, "")
	at := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == labelsPrompt })
	steps[at].answer = "release=other"
	steps = slices.Insert(steps, at+1, scriptedStep{prompt: labelsPrompt, answer: "team=identity"})
	steps[slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == annotationsPrompt })].answer = "example.com/owner=identity team"
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	if !strings.Contains(out.String(), "the label release is one of the PodMonitor's labels too") {
		t.Errorf("the overlap was not refused:\n%s", out)
	}
	if got := w.config.Labels; !slices.Equal(got, []keyValue{{"team", "identity"}}) {
		t.Errorf("the labels are %v", got)
	}
	if got := w.config.Annotations; !slices.Equal(got, []keyValue{{"example.com/owner", "identity team"}}) {
		t.Errorf("the annotations are %v", got)
	}

	flags := kubernetesFlags()
	flags.Metrics, flags.PodMonitorLabels, flags.Labels = metricsPodMonitor, podMonitorLabelSet{{"release", "prom"}}, labelSet{{"release", "prom"}}
	w, _, out, _ = testWizard(t, flags, nil)
	if err := w.setup(); err == nil || !strings.Contains(err.Error(), "invalid --labels") {
		t.Errorf("setup returned %v, want the overlap refused\n%s", err, out)
	}

	flags = kubernetesFlags()
	flags.Labels, flags.Annotations = labelSet(operatorLabels), annotationSet(operatorAnnotations)
	w, _, out, _ = testWizard(t, flags, nil)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if !slices.Equal(w.config.Labels, operatorLabels) || !slices.Equal(w.config.Annotations, operatorAnnotations) {
		t.Errorf("by flag, the labels are %v and the annotations %v", w.config.Labels, w.config.Annotations)
	}
}

// A PodMonitor label app, which every wizard since --podmonitor-labels took, is taken still: the
// PodMonitor carries no app label of its own, and an answers file holding one regenerates. On every
// object, where the pod templates' app is the selectors', it is refused.
func TestAnswers_APodMonitorLabelAppStillRegenerates(t *testing.T) {
	config := goldenConfig(deploymentKubernetes, "postgres")
	config.Metrics, config.PodMonitorLabels = metricsPodMonitor, []keyValue{{"app", "prometheus"}}
	dir := t.TempDir()
	paths := writeDeployment(t, config, dir)
	if _, out, err := runWithAnswers(t, "--answers", paths.answers, "--keep-secrets", "--output", dir); err != nil {
		t.Fatalf("an answers file with the PodMonitor label app: %v\n%s", err, out)
	}
	monitors := 0
	for _, doc := range yamlDocuments(t, readFile(t, paths.description)) {
		if doc["kind"] != "PodMonitor" {
			continue
		}
		monitors++
		if got := at[string](t, doc, "metadata", "labels", "app"); got != "prometheus" {
			t.Errorf("the regenerated PodMonitor is labeled app: %q, want prometheus", got)
		}
	}
	if monitors != 1 {
		t.Errorf("the regenerated manifest has %d PodMonitors, want one", monitors)
	}
	if answers := readFile(t, paths.answers); !strings.Contains(answers, "\npodmonitor-labels: \"app=prometheus\"\n") {
		t.Errorf("the regenerated answers file lost the label:\n%s", answers)
	}
	if _, err := parseLabels("app=prometheus"); err == nil {
		t.Error("--labels takes app, which the pod templates' selectors match")
	}
	if _, err := parsePodMonitorLabels("app.kubernetes.io/name=x"); err == nil {
		t.Error("--podmonitor-labels takes a standard label, which the PodMonitor carries already")
	}
}

// A Secret the operator creates carries the labels every other object does, the standard ones and
// theirs, and their annotations, from its creation, which an admission policy checks: the printed
// command writes it locally, labels and annotates it there, quoting a pair the shell would split,
// and only then creates it. The auth server's TLS Secret is its component's; the pull secret, which
// both pods name, is no component's.
func TestKubernetesInstructions_CreateSecretsWithTheLabels(t *testing.T) {
	config := kubernetesConfig()
	config.Routing, config.TLS, config.TLSSecretAuth, config.TLSSecretAdmin = routingIngress, tlsSecrets, authCertificateSecret, adminCertificateSecret
	config.ImageRepository, config.ImagePullSecret = "registry.example.com/mirror/goiabada", "registry-credentials"
	const standard = "app.kubernetes.io/name=goiabada app.kubernetes.io/instance=identity "
	const shared = "app.kubernetes.io/part-of=goiabada app.kubernetes.io/version=latest app.kubernetes.io/managed-by=goiabada-setup"
	tls := "kubectl create secret tls goiabada-tls-auth -n identity --cert=auth.crt --key=auth.key --dry-run=client -o yaml |\n"
	pull := "kubectl create secret docker-registry registry-credentials -n identity --docker-server=registry.example.com --docker-username=<user> --docker-password=<password> --dry-run=client -o yaml |\n"
	for _, tc := range []struct {
		name        string
		labels      []keyValue
		annotations []keyValue
		want        []string
	}{
		{name: "no labels of the operator's", want: []string{
			tls + "       kubectl label --local -f - " + standard + "app.kubernetes.io/component=authserver " + shared + " -o yaml |\n       kubectl create -f -\n",
			pull + "       kubectl label --local -f - " + standard + shared + " -o yaml |\n       kubectl create -f -\n",
		}},
		{name: "the operator's labels and annotations", labels: []keyValue{{"team", "identity"}}, annotations: operatorAnnotations, want: []string{
			tls + "       kubectl label --local -f - " + standard + "app.kubernetes.io/component=authserver " + shared + " team=identity -o yaml |\n" +
				"       kubectl annotate --local -f - 'example.com/owner=identity team: on call' -o yaml |\n       kubectl create -f -\n",
			pull + "       kubectl label --local -f - " + standard + shared + " team=identity -o yaml |\n" +
				"       kubectl annotate --local -f - 'example.com/owner=identity team: on call' -o yaml |\n       kubectl create -f -\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.Labels, config.Annotations = tc.labels, tc.annotations
			var buf strings.Builder
			printDeployStep(&console{w: &buf}, config, config.Deployment.defaultPaths(), 2)
			for _, want := range tc.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("the deploy step has no command:\n%s\nit reads:\n%s", want, buf.String())
				}
			}
		})
	}
}
