package main

import (
	"bytes"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The metrics listeners' ports, each server's default, which the manifest's `metrics` container
// ports name (#400 decision 3), and the switch each server reads to open its listener.
var metricsListeners = map[string]struct {
	port     int
	variable string
}{
	"goiabada-authserver":   {9190, "GOIABADA_AUTHSERVER_METRICS_ENABLED"},
	"goiabada-adminconsole": {9191, "GOIABADA_ADMINCONSOLE_METRICS_ENABLED"},
}

// The prompts of the metrics step: the question, none by default, the PodMonitor's labels, blank by
// default, and the scraper's namespace, monitoring by default (#400 decisions 7 and 8).
const (
	metricsPrompt          = "Expose Prometheus metrics? [1-3] [1]: "
	podMonitorLabelsPrompt = "Labels your Prometheus selects PodMonitors by (e.g., release=kube-prometheus-stack), blank for none: "
	metricsNamespacePrompt = "Namespace your metrics scraper runs in [monitoring]: "
)

// metricsConfig is kubernetesConfig exposing its metrics as exposure.
func metricsConfig(exposure metricsExposure) *Config {
	config := kubernetesConfig()
	config.Metrics = exposure
	return config
}

// podContainer is the one container of the Deployment's pod template.
func podContainer(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	podSpec := at[map[string]any](t, deployment, "spec", "template", "spec")
	return only[map[string]any](t, at[[]any](t, podSpec, "containers"), "the containers")
}

// namedPort is the container port of that name, nil when there is none.
func namedPort(t *testing.T, container map[string]any, name string) map[string]any {
	t.Helper()
	for _, p := range at[[]any](t, container, "ports") {
		port := p.(map[string]any)
		if port["name"] == name {
			return port
		}
	}
	return nil
}

// selects reads a Kubernetes label selector as the API server does, for the two forms it can take
// here, matchLabels and matchExpressions with In, and refuses any other operator rather than read it.
func selects(t *testing.T, selector, labels map[string]any) bool {
	t.Helper()
	for key, value := range mapOrEmpty(selector["matchLabels"]) {
		if labels[key] != value {
			return false
		}
	}
	expressions, _ := selector["matchExpressions"].([]any)
	for _, e := range expressions {
		expression := e.(map[string]any)
		if expression["operator"] != "In" {
			t.Fatalf("the selector uses operator %v, which this test does not read", expression["operator"])
		}
		value, ok := labels[expression["key"].(string)]
		if !ok || !slices.Contains(expression["values"].([]any), value) {
			return false
		}
	}
	return len(selector) > 0
}

func mapOrEmpty(node any) map[string]any {
	m, _ := node.(map[string]any)
	return m
}

// documentComment is the block of comment lines directly above the document of that kind and name,
// between its `---` and its apiVersion.
func documentComment(t *testing.T, content, kind, name string) string {
	t.Helper()
	for _, doc := range strings.Split(content, "\n---\n") {
		if !strings.Contains(doc, "\nkind: "+kind+"\n") || !strings.Contains(doc, "\n  name: "+name+"\n") {
			continue
		}
		var comment []string
		for _, line := range strings.Split(doc, "\n") {
			if !strings.HasPrefix(line, "#") {
				break
			}
			comment = append(comment, strings.TrimSpace(strings.TrimPrefix(line, "#")))
		}
		return strings.Join(comment, " ")
	}
	t.Fatalf("no %s document named %s", kind, name)
	return ""
}

// Every Kubernetes manifest turns on the per-request log records in both ConfigMaps, as every
// Compose output and the env file always have, and leaves the format at text, the server's own
// default and every other output's (#400 decision 10).
func TestKubernetesManifest_TurnsRequestLoggingOnInBothServers(t *testing.T) {
	checked := 0
	for _, testCase := range goldenCases() {
		if testCase.deployment != deploymentKubernetes {
			continue
		}
		config := testCase.config()
		t.Run(testCase.name, func(t *testing.T) {
			env := serverEnvironments(t, config, descriptionOf(config))
			for _, server := range []string{"AUTHSERVER", "ADMINCONSOLE"} {
				if got := env[server]["GOIABADA_"+server+"_LOG_HTTP_REQUESTS"]; got != "true" {
					t.Errorf("the %s ConfigMap sets GOIABADA_%s_LOG_HTTP_REQUESTS to %q, want \"true\"", server, server, got)
				}
				if format, ok := env[server]["GOIABADA_"+server+"_LOG_FORMAT"]; ok && format != "text" {
					t.Errorf("the %s ConfigMap sets the log format to %q", server, format)
				}
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no Kubernetes golden case, so this checked nothing")
	}
}

// With metrics off, which is the default, the manifest says nothing about them: no switch, no port,
// no annotation and no PodMonitor (#400 decision 7).
func TestKubernetesManifest_SaysNothingOfMetricsWhenOff(t *testing.T) {
	config := metricsConfig(metricsNone)
	config.NetworkPolicy = true
	content := descriptionOf(config)
	for _, unwanted := range []string{"METRICS", "9190", "9191", "prometheus", "PodMonitor", "metrics"} {
		if strings.Contains(content, unwanted) {
			t.Errorf("the manifest names %q with metrics off", unwanted)
		}
	}
	docs := kubernetesDocuments(t, config)
	for _, w := range workloads {
		policy := docs["NetworkPolicy"][w.deployment]
		if rules := at[[]any](t, policy, "spec", "ingress"); len(rules) != 1 {
			t.Errorf("%s's policy has %d ingress rules with metrics off, want 1", w.deployment, len(rules))
		}
	}
}

// Either yes answer turns each server's metrics listener on in its own ConfigMap and declares a
// container port named metrics on its default port, beside the server's own. Pod annotations write
// the three prometheus.io keys on both pod templates and no PodMonitor; the PodMonitor answer writes
// one monitoring.coreos.com/v1 PodMonitor selecting both Deployments' pods by the metrics port,
// carrying the labels given, and no annotation (#400 decision 7).
func TestKubernetesManifest_ExposesMetricsAsAnswered(t *testing.T) {
	for _, exposure := range []metricsExposure{metricsAnnotations, metricsPodMonitor} {
		t.Run(string(exposure), func(t *testing.T) {
			config := metricsConfig(exposure)
			docs := kubernetesDocuments(t, config)
			env := serverEnvironments(t, config, descriptionOf(config))
			for _, w := range workloads {
				t.Run(w.deployment, func(t *testing.T) {
					listener := metricsListeners[w.deployment]
					server := strings.ToUpper(strings.TrimPrefix(w.deployment, "goiabada-"))
					if got := env[server][listener.variable]; got != "true" {
						t.Errorf("%s sets %s to %q, want \"true\"", w.configMap, listener.variable, got)
					}
					for other, l := range metricsListeners {
						if other != w.deployment {
							if _, ok := env[server][l.variable]; ok {
								t.Errorf("%s is handed %s, the other server's switch", w.configMap, l.variable)
							}
						}
					}

					deployment := deploymentNamed(t, docs, w.deployment)
					container := podContainer(t, deployment)
					port := namedPort(t, container, "metrics")
					if port == nil {
						t.Fatalf("the container declares no port named metrics: %v", container["ports"])
					}
					if at[int](t, port, "containerPort") != listener.port {
						t.Errorf("the metrics port is %v, want %d", port, listener.port)
					}
					if ports := at[[]any](t, container, "ports"); len(ports) != 2 {
						t.Errorf("the container declares ports %v, want the server's and metrics", ports)
					}

					annotations := mapOrEmpty(at[map[string]any](t, deployment, "spec", "template", "metadata")["annotations"])
					if exposure == metricsAnnotations {
						want := map[string]any{
							"prometheus.io/scrape": "true",
							"prometheus.io/port":   strconv.Itoa(listener.port),
							"prometheus.io/path":   "/metrics",
						}
						if !reflect.DeepEqual(annotations, want) {
							t.Errorf("the pod template is annotated %v, want %v", annotations, want)
						}
					} else if len(annotations) != 0 {
						t.Errorf("the pod template is annotated %v with a PodMonitor", annotations)
					}
				})
			}

			monitors := docs["PodMonitor"]
			if exposure == metricsAnnotations {
				if len(monitors) != 0 {
					t.Errorf("pod annotations write PodMonitors %v", slices.Sorted(maps.Keys(monitors)))
				}
				return
			}
			if len(monitors) != 1 {
				t.Fatalf("the manifest has PodMonitors %v, want one", slices.Sorted(maps.Keys(monitors)))
			}
			for name, monitor := range monitors {
				if got := at[string](t, monitor, "apiVersion"); got != "monitoring.coreos.com/v1" {
					t.Errorf("the PodMonitor's apiVersion is %q, want monitoring.coreos.com/v1", got)
				}
				if got := at[string](t, monitor, "metadata", "namespace"); got != config.K8sNamespace {
					t.Errorf("the PodMonitor is in namespace %q, want %q", got, config.K8sNamespace)
				}
				if labels, ok := at[map[string]any](t, monitor, "metadata")["labels"]; ok {
					t.Errorf("the PodMonitor carries labels %v, and none was given", labels)
				}
				selector := at[map[string]any](t, monitor, "spec", "selector")
				for _, w := range workloads {
					pods := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "metadata", "labels")
					if !selects(t, selector, pods) {
						t.Errorf("the PodMonitor's selector %v does not select %s's pods %v", selector, w.deployment, pods)
					}
				}
				if selects(t, selector, map[string]any{"app": "something-else"}) {
					t.Errorf("the PodMonitor's selector %v selects pods that are not Goiabada's", selector)
				}
				endpoint := only[map[string]any](t, at[[]any](t, monitor, "spec", "podMetricsEndpoints"), "the PodMonitor's endpoints")
				if at[string](t, endpoint, "port") != "metrics" || at[string](t, endpoint, "path") != "/metrics" {
					t.Errorf("the PodMonitor scrapes %v, want port metrics and path /metrics", endpoint)
				}
				comment := strings.Join(strings.Fields(documentComment(t, descriptionOf(config), "PodMonitor", name)), " ")
				for _, said := range []string{"selects only the PodMonitors", "release: <", "CRDs"} {
					if !strings.Contains(comment, said) {
						t.Errorf("the PodMonitor's comment does not say %q: %q", said, comment)
					}
				}
			}
		})
	}
}

// The PodMonitor carries the labels the operator's Prometheus selects PodMonitors by, in the order
// given, and they move nothing else (#400 decision 7).
func TestKubernetesManifest_LabelsThePodMonitorAsGiven(t *testing.T) {
	config := metricsConfig(metricsPodMonitor)
	config.PodMonitorLabels = []podMonitorLabel{{"release", "kube-prometheus-stack"}, {"example.com/team", "identity"}}
	monitors := kubernetesDocuments(t, config)["PodMonitor"]
	if len(monitors) != 1 {
		t.Fatalf("the manifest has PodMonitors %v, want one", slices.Sorted(maps.Keys(monitors)))
	}
	for _, monitor := range monitors {
		want := map[string]any{"release": "kube-prometheus-stack", "example.com/team": "identity"}
		if got := at[map[string]any](t, monitor, "metadata", "labels"); !reflect.DeepEqual(got, want) {
			t.Errorf("the PodMonitor is labeled %v, want %v", got, want)
		}
	}
	content := descriptionOf(config)
	if strings.Index(content, yamlQuote("release")+":") > strings.Index(content, yamlQuote("example.com/team")+":") {
		t.Error("the labels are not written in the order given")
	}
}

// With the NetworkPolicies on, each gains a second ingress rule admitting the scraper's namespace
// to its server's metrics port and nothing else, while the first rule stays exactly the rule it is
// with metrics off; the comment says how to admit a scraper in another namespace. With the
// NetworkPolicies off, metrics write none (#400 decision 8).
func TestKubernetesManifest_AdmitsTheScraperToTheMetricsPortAlone(t *testing.T) {
	without := metricsConfig(metricsNone)
	without.NetworkPolicy = true
	before := kubernetesDocuments(t, without)

	for _, exposure := range []metricsExposure{metricsAnnotations, metricsPodMonitor} {
		t.Run(string(exposure), func(t *testing.T) {
			config := metricsConfig(exposure)
			config.NetworkPolicy = true
			config.MetricsNamespace = "observability"
			docs := kubernetesDocuments(t, config)
			content := descriptionOf(config)
			for _, w := range workloads {
				t.Run(w.deployment, func(t *testing.T) {
					rules := at[[]any](t, docs["NetworkPolicy"][w.deployment], "spec", "ingress")
					if len(rules) != 2 {
						t.Fatalf("the policy has ingress rules %v, want the existing one and the scraper's", rules)
					}
					existing := at[[]any](t, before["NetworkPolicy"][w.deployment], "spec", "ingress")[0]
					if !reflect.DeepEqual(rules[0], existing) {
						t.Errorf("the first rule is %v, want it unchanged from %v", rules[0], existing)
					}
					scraper := rules[1].(map[string]any)
					wantFrom := []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "observability"}}}}
					if got := at[[]any](t, scraper, "from"); !reflect.DeepEqual(got, wantFrom) {
						t.Errorf("the scraper's rule admits %v, want %v", got, wantFrom)
					}
					wantPorts := []any{map[string]any{"protocol": "TCP", "port": metricsListeners[w.deployment].port}}
					if got := at[[]any](t, scraper, "ports"); !reflect.DeepEqual(got, wantPorts) {
						t.Errorf("the scraper's rule opens %v, want %v", got, wantPorts)
					}
					comment := strings.Join(strings.Fields(documentComment(t, content, "NetworkPolicy", w.deployment)), " ")
					for _, said := range []string{"observability", "metrics port", strconv.Itoa(metricsListeners[w.deployment].port), "another namespace"} {
						if !strings.Contains(comment, said) {
							t.Errorf("the policy's comment does not say %q: %q", said, comment)
						}
					}
				})
			}
		})
	}

	t.Run("without NetworkPolicies", func(t *testing.T) {
		config := metricsConfig(metricsPodMonitor)
		config.MetricsNamespace = "observability"
		if policies := kubernetesDocuments(t, config)["NetworkPolicy"]; len(policies) != 0 {
			t.Errorf("metrics wrote NetworkPolicies %v with none asked for", slices.Sorted(maps.Keys(policies)))
		}
	})
}

// metricsScript is the interactive Kubernetes script answering the metrics question with exposure,
// 1 to 3 or blank, the PodMonitor's labels with labels when 3 asks for them, and, with the
// NetworkPolicies on, the scraper's namespace with namespace.
func metricsScript(t *testing.T, exposure, labels string, networkPolicy bool, namespace string) []scriptedStep {
	t.Helper()
	answers := map[string]string{metricsPrompt: exposure}
	if networkPolicy {
		answers[networkPolicyPrompt] = "y"
	}
	steps := withAnswers(t, deploymentKubernetes, answers)
	at := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == metricsPrompt })
	var followUps []scriptedStep
	if exposure == "3" {
		followUps = append(followUps, scriptedStep{prompt: podMonitorLabelsPrompt, answer: labels})
	}
	if networkPolicy && exposure != "" && exposure != "1" {
		followUps = append(followUps, scriptedStep{prompt: metricsNamespacePrompt, answer: namespace})
	}
	return slices.Insert(steps, at+1, followUps...)
}

// Kubernetes asks whether to expose the metrics and to which kind of scraper, none by default, and
// --metrics answers without a prompt, none when left out. The question says which scraper reads
// which answer; the answer is what the manifest writes (#400 decision 7).
func TestWizard_KubernetesAsksWhetherToExposeMetrics(t *testing.T) {
	byFlag := func(exposure metricsExposure) *CLIFlags {
		f := kubernetesFlags()
		f.Metrics = exposure
		return f
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  metricsExposure
	}{
		"prompted, the default": {&CLIFlags{}, metricsScript(t, "", "", false, ""), metricsNone},
		"prompted, 1":           {&CLIFlags{}, metricsScript(t, "1", "", false, ""), metricsNone},
		"prompted, 2":           {&CLIFlags{}, metricsScript(t, "2", "", false, ""), metricsAnnotations},
		"prompted, 3":           {&CLIFlags{}, metricsScript(t, "3", "", false, ""), metricsPodMonitor},
		"by flag, left out":     {byFlag(""), nil, metricsNone},
		"by flag, none":         {byFlag(metricsNone), nil, metricsNone},
		"by flag, annotations":  {byFlag(metricsAnnotations), nil, metricsAnnotations},
		"by flag, podmonitor":   {byFlag(metricsPodMonitor), nil, metricsPodMonitor},
		"by flag, labels ignored": {func() *CLIFlags {
			f := byFlag(metricsAnnotations)
			f.PodMonitorLabels = []podMonitorLabel{{"release", "x"}}
			return f
		}(), nil, metricsAnnotations},
		"by flag, namespace ignored": {func() *CLIFlags { f := byFlag(metricsPodMonitor); f.MetricsNamespace = "observability"; return f }(), nil, metricsPodMonitor},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.Metrics != tc.want {
				t.Errorf("Metrics is %q, want %q", w.config.Metrics, tc.want)
			}
			if len(w.config.PodMonitorLabels) != 0 || w.config.MetricsNamespace != "" {
				t.Errorf("labels %v and namespace %q were taken without being asked", w.config.PodMonitorLabels, w.config.MetricsNamespace)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			_, on := serverEnvironments(t, w.config, string(written))["AUTHSERVER"]["GOIABADA_AUTHSERVER_METRICS_ENABLED"]
			if on != (tc.want != metricsNone) {
				t.Errorf("the auth server's metrics switch is written: %v, want %v", on, tc.want != metricsNone)
			}
			if got := strings.Contains(string(written), "kind: PodMonitor"); got != (tc.want == metricsPodMonitor) {
				t.Errorf("the manifest carries a PodMonitor: %v, want %v", got, tc.want == metricsPodMonitor)
			}
			said := strings.Join(strings.Fields(out.String()), " ")
			if tc.steps != nil {
				for _, want := range []string{"prometheus.io/scrape", "kube-prometheus-stack", "PodMonitor", "Prometheus Operator", "9190", "9191"} {
					if !strings.Contains(said, want) {
						t.Errorf("the question does not say %q:\n%s", want, out)
					}
				}
			} else {
				wantReport := map[metricsExposure]string{metricsNone: "Metrics: none", metricsAnnotations: "Metrics: pod annotations", metricsPodMonitor: "Metrics: a PodMonitor"}[tc.want]
				if !strings.Contains(said, wantReport) {
					t.Errorf("the run does not report %q:\n%s", wantReport, out)
				}
			}
		})
	}
}

// Choosing the PodMonitor asks for the labels the operator's Prometheus selects PodMonitors by,
// none by default, asking again for one that is no Kubernetes label; --podmonitor-labels answers
// without a prompt (#400 decision 7).
func TestWizard_ThePodMonitorAsksForItsLabels(t *testing.T) {
	invalidThenValid := metricsScript(t, "3", "release", false, "")
	at := slices.IndexFunc(invalidThenValid, func(s scriptedStep) bool { return s.prompt == podMonitorLabelsPrompt })
	invalidThenValid = slices.Insert(invalidThenValid, at+1, scriptedStep{prompt: podMonitorLabelsPrompt, answer: "release=kube-prometheus-stack"})
	byFlag := func(labels []podMonitorLabel) *CLIFlags {
		f := kubernetesFlags()
		f.Metrics = metricsPodMonitor
		f.PodMonitorLabels = labels
		return f
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  []podMonitorLabel
	}{
		"prompted, blank":            {&CLIFlags{}, metricsScript(t, "3", "", false, ""), nil},
		"prompted, one":              {&CLIFlags{}, metricsScript(t, "3", "release=kube-prometheus-stack", false, ""), []podMonitorLabel{{"release", "kube-prometheus-stack"}}},
		"prompted, two with a space": {&CLIFlags{}, metricsScript(t, "3", "release=prom, team=identity", false, ""), []podMonitorLabel{{"release", "prom"}, {"team", "identity"}}},
		"prompted, invalid first":    {&CLIFlags{}, invalidThenValid, []podMonitorLabel{{"release", "kube-prometheus-stack"}}},
		"by flag, left out":          {byFlag(nil), nil, nil},
		"by flag, one":               {byFlag([]podMonitorLabel{{"release", "kube-prometheus-stack"}}), nil, []podMonitorLabel{{"release", "kube-prometheus-stack"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if !slices.Equal(w.config.PodMonitorLabels, tc.want) {
				t.Errorf("PodMonitorLabels is %v, want %v", w.config.PodMonitorLabels, tc.want)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			for _, label := range tc.want {
				if !strings.Contains(string(written), "    "+yamlQuote(label.key)+": "+yamlQuote(label.value)+"\n") {
					t.Errorf("the manifest does not label the PodMonitor %s: %s", label.key, label.value)
				}
			}
			if name == "prompted, invalid first" && !strings.Contains(out.String(), "Invalid labels") {
				t.Errorf("the invalid answer was not refused:\n%s", out)
			}
		})
	}
}

// A label set is key=value pairs separated by commas, each key and value one Kubernetes accepts;
// anything else is refused saying what is wrong (Kubernetes docs, "Labels and Selectors", syntax and
// character set).
func TestParsePodMonitorLabels(t *testing.T) {
	for input, want := range map[string][]podMonitorLabel{
		"":                                 nil,
		"  ":                               nil,
		"release=kube-prometheus-stack":    {{"release", "kube-prometheus-stack"}},
		"release=prom,team=identity":       {{"release", "prom"}, {"team", "identity"}},
		" release = prom , team=identity ": {{"release", "prom"}, {"team", "identity"}},
		"example.com/team=identity":        {{"example.com/team", "identity"}},
		"empty=":                           {{"empty", ""}},
		"a_b.c-d=X_y.Z-9":                  {{"a_b.c-d", "X_y.Z-9"}},
		strings.Repeat("k", 63) + "=v":     {{strings.Repeat("k", 63), "v"}},
		"k=" + strings.Repeat("v", 63):     {{"k", strings.Repeat("v", 63)}},
	} {
		got, err := parsePodMonitorLabels(input)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("parsePodMonitorLabels(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{
		"release",
		"=prom",
		"release=prom,",
		"release=prom,release=other",
		"rel ease=prom",
		"release=kube prometheus",
		"release=\"prom\"",
		"-release=prom",
		"release=prom-",
		strings.Repeat("k", 64) + "=v",
		"k=" + strings.Repeat("v", 64),
		"Example.com/team=x",
		"example.com/=x",
		"/team=x",
		"a/b/c=x",
		"release=prom: x",
		"release=prom#x",
	} {
		if got, err := parsePodMonitorLabels(input); err == nil {
			t.Errorf("parsePodMonitorLabels(%q) = %v, want it refused", input, got)
		}
	}
}

// With the NetworkPolicies on, either yes answer asks which namespace the scraper runs in,
// monitoring by default, asking again for one that is no namespace; --metrics-namespace answers
// without a prompt. With them off, or metrics off, it is not asked (#400 decision 8).
func TestWizard_AsksTheScrapersNamespaceUnderNetworkPolicies(t *testing.T) {
	invalidThenValid := metricsScript(t, "2", "", true, "Not_A_Namespace")
	at := slices.IndexFunc(invalidThenValid, func(s scriptedStep) bool { return s.prompt == metricsNamespacePrompt })
	invalidThenValid = slices.Insert(invalidThenValid, at+1, scriptedStep{prompt: metricsNamespacePrompt, answer: "observability"})
	byFlag := func(exposure metricsExposure, networkPolicy bool, namespace string) *CLIFlags {
		f := kubernetesFlags()
		f.Metrics, f.NetworkPolicy, f.MetricsNamespace = exposure, networkPolicy, namespace
		return f
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  string
	}{
		"prompted, the default":        {&CLIFlags{}, metricsScript(t, "2", "", true, ""), "monitoring"},
		"prompted, another":            {&CLIFlags{}, metricsScript(t, "3", "", true, "observability"), "observability"},
		"prompted, invalid first":      {&CLIFlags{}, invalidThenValid, "observability"},
		"prompted, metrics off":        {&CLIFlags{}, metricsScript(t, "1", "", true, ""), ""},
		"prompted, no NetworkPolicies": {&CLIFlags{}, metricsScript(t, "2", "", false, ""), ""},
		"by flag, left out":            {byFlag(metricsAnnotations, true, ""), nil, "monitoring"},
		"by flag, another":             {byFlag(metricsPodMonitor, true, "observability"), nil, "observability"},
		"by flag, metrics off":         {byFlag(metricsNone, true, "observability"), nil, ""},
		"by flag, no NetworkPolicies":  {byFlag(metricsAnnotations, false, "observability"), nil, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.MetricsNamespace != tc.want {
				t.Errorf("MetricsNamespace is %q, want %q", w.config.MetricsNamespace, tc.want)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !strings.Contains(string(written), "kubernetes.io/metadata.name: "+yamlQuote(tc.want)+"\n") {
				t.Errorf("the manifest admits no namespace %s", tc.want)
			}
			if name == "prompted, invalid first" && !strings.Contains(out.String(), "Invalid namespace") {
				t.Errorf("the invalid answer was not refused:\n%s", out)
			}
		})
	}

	t.Run("an invalid flag is refused", func(t *testing.T) {
		w, _, out, _ := testWizard(t, byFlag(metricsAnnotations, true, "Not_A_Namespace"), nil)
		err := w.setup()
		if err == nil || !strings.Contains(err.Error(), "--metrics-namespace") {
			t.Errorf("setup: %v, want --metrics-namespace refused\n%s", err, out)
		}
	})
}

// --metrics reads none, annotations or podmonitor in any case and refuses anything else by the
// flag's name; --podmonitor-labels refuses a value that is no label set by its name; and the usage
// lists the three under Kubernetes (#400 decisions 7 and 8).
func TestParseFlags_TheMetricsFlags(t *testing.T) {
	for args, want := range map[string]metricsExposure{
		"":                      "",
		"--metrics=none":        metricsNone,
		"--metrics=annotations": metricsAnnotations,
		"--metrics=PodMonitor":  metricsPodMonitor,
		"--metrics podmonitor":  metricsPodMonitor,
	} {
		flags, err := parseFlags(strings.Fields(args), io.Discard)
		if err != nil {
			t.Fatalf("parseFlags(%q): %v", args, err)
		}
		if flags.Metrics != want {
			t.Errorf("parseFlags(%q) reads %q, want %q", args, flags.Metrics, want)
		}
	}
	for _, value := range []string{"yes", "", "servicemonitor", "annotations,podmonitor"} {
		_, err := parseFlags([]string{"--metrics=" + value}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "for flag -metrics: use none, annotations or podmonitor") {
			t.Errorf("parseFlags(--metrics=%s): %v, want the value refused by the flag's name", value, err)
		}
	}

	flags, err := parseFlags([]string{"--podmonitor-labels=release=prom,team=identity", "--metrics-namespace=observability"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if want := []podMonitorLabel{{"release", "prom"}, {"team", "identity"}}; !slices.Equal(flags.PodMonitorLabels, want) {
		t.Errorf("--podmonitor-labels reads %v, want %v", flags.PodMonitorLabels, want)
	}
	if flags.MetricsNamespace != "observability" {
		t.Errorf("--metrics-namespace reads %q", flags.MetricsNamespace)
	}
	if _, err := parseFlags([]string{"--podmonitor-labels=release"}, io.Discard); err == nil || !strings.Contains(err.Error(), "for flag -podmonitor-labels") {
		t.Errorf("parseFlags(--podmonitor-labels=release): %v, want the value refused by the flag's name", err)
	}

	var stderr bytes.Buffer
	_, _ = parseFlags([]string{"-h"}, &stderr)
	usage := stderr.String()
	section := strings.Index(usage, "Kubernetes Options:")
	next := strings.Index(usage, "Native Binaries Options:")
	for _, name := range []string{"--metrics=", "--podmonitor-labels", "--metrics-namespace"} {
		at := strings.Index(usage, name)
		if section < 0 || at < section || at > next {
			t.Errorf("%s is not listed under the Kubernetes options:\n%s", name, usage)
		}
	}
}

// The metrics flags are ignored by every type that does not deploy to Kubernetes, as
// --network-policy is (#400, the assumption on the new flags).
func TestWizard_MetricsFlagsAreIgnoredOutsideKubernetes(t *testing.T) {
	for _, flags := range []CLIFlags{
		{DeploymentType: "production", DBType: "postgres", AuthServerURL: "https://auth.example.org"},
		{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true},
		{DeploymentType: "local", DBType: "sqlite"},
	} {
		t.Run(flags.DeploymentType, func(t *testing.T) {
			flags.Metrics, flags.NetworkPolicy, flags.MetricsNamespace = metricsPodMonitor, true, "observability"
			flags.PodMonitorLabels = []podMonitorLabel{{"release", "prom"}}
			w, _, out, _ := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if w.config.Metrics != "" || w.config.PodMonitorLabels != nil || w.config.MetricsNamespace != "" {
				t.Errorf("%s holds metrics %q, labels %v and namespace %q", flags.DeploymentType, w.config.Metrics, w.config.PodMonitorLabels, w.config.MetricsNamespace)
			}
			// The output names the test's temporary directory, so it is searched for the report and the
			// question rather than for the word.
			for _, said := range []string{"Metrics:", "Prometheus", "PodMonitor"} {
				if strings.Contains(out.String(), said) {
					t.Errorf("%s reports %q:\n%s", flags.DeploymentType, said, out)
				}
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(written), "METRICS") {
				t.Errorf("%s's file names a metrics setting", flags.DeploymentType)
			}
		})
	}
}

// The summary says what was chosen: the exposure, the PodMonitor's labels, and the scraper's
// namespace when the NetworkPolicies admit it (#400 decision 7).
func TestSummary_ReportsTheMetricsAnswer(t *testing.T) {
	cases := map[string]struct {
		configure func(*Config)
		want      []string
		unwanted  []string
	}{
		"none":        {func(c *Config) {}, []string{"Metrics: none"}, []string{"scraper"}},
		"annotations": {func(c *Config) { c.Metrics = metricsAnnotations }, []string{"Metrics: pod annotations"}, []string{"scraper"}},
		"podmonitor": {func(c *Config) {
			c.Metrics = metricsPodMonitor
			c.PodMonitorLabels = []podMonitorLabel{{"release", "prom"}}
		}, []string{"Metrics: a PodMonitor labeled release=prom"}, []string{"scraper"}},
		"podmonitor, no labels": {func(c *Config) { c.Metrics = metricsPodMonitor }, []string{"Metrics: a PodMonitor, unlabeled"}, nil},
		"with NetworkPolicies": {func(c *Config) {
			c.Metrics, c.NetworkPolicy, c.MetricsNamespace = metricsAnnotations, true, "observability"
		}, []string{"Metrics: pod annotations", "Metrics scraper: namespace observability"}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			config := kubernetesConfig()
			tc.configure(config)
			var buf bytes.Buffer
			printSummary(&console{w: &buf}, config)
			said := strings.Join(strings.Fields(buf.String()), " ")
			for _, want := range tc.want {
				if !strings.Contains(said, want) {
					t.Errorf("the summary does not say %q:\n%s", want, buf.String())
				}
			}
			for _, unwanted := range tc.unwanted {
				if strings.Contains(said, unwanted) {
					t.Errorf("the summary says %q:\n%s", unwanted, buf.String())
				}
			}
		})
	}
	t.Run("not Kubernetes", func(t *testing.T) {
		var buf bytes.Buffer
		printSummary(&console{w: &buf}, goldenConfig(deploymentNative, "postgres"))
		if strings.Contains(buf.String(), "Metrics") {
			t.Errorf("the native summary reports metrics:\n%s", buf.String())
		}
	})
}

// The completion message says what was chosen and what it needs: with metrics off nothing; with pod
// annotations, which scrapers honor them and that kube-prometheus-stack does not; with a PodMonitor,
// that it needs the Operator's CRDs and is selected only by a matching Prometheus; and with the
// NetworkPolicies on, the namespace they admit (#400 decisions 7 and 8).
func TestKubernetesInstructions_SayWhatTheMetricsAnswerNeeds(t *testing.T) {
	const monitoringDocs = "https://goiabada.dev/production-deployment/monitoring/"
	cases := map[string]struct {
		configure func(*Config)
		want      []string
	}{
		"annotations": {func(c *Config) { c.Metrics = metricsAnnotations }, []string{"9190", "9191", "prometheus.io/scrape", "kube-prometheus-stack ignores", "--metrics=podmonitor", monitoringDocs}},
		"podmonitor":  {func(c *Config) { c.Metrics = metricsPodMonitor }, []string{"9190", "9191", "CRDs", "kubectl apply exits 1", "podMonitorSelector", monitoringDocs}},
		"with NetworkPolicies": {func(c *Config) {
			c.Metrics, c.NetworkPolicy, c.MetricsNamespace = metricsPodMonitor, true, "observability"
		}, []string{"observability", "metrics ports alone"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			config := kubernetesConfig()
			tc.configure(config)
			var buf bytes.Buffer
			printKubernetesInstructions(&console{w: &buf}, config, outputPaths{"goiabada-k8s.yaml", "goiabada-secrets.yaml"})
			said := strings.Join(strings.Fields(buf.String()), " ")
			for _, want := range tc.want {
				if !strings.Contains(said, want) {
					t.Errorf("the message does not say %q:\n%s", want, buf.String())
				}
			}
		})
	}
	t.Run("none", func(t *testing.T) {
		var buf bytes.Buffer
		printKubernetesInstructions(&console{w: &buf}, kubernetesConfig(), outputPaths{"goiabada-k8s.yaml", "goiabada-secrets.yaml"})
		if strings.Contains(strings.ToLower(buf.String()), "metrics") {
			t.Errorf("the message speaks of metrics with them off:\n%s", buf.String())
		}
	})
}
