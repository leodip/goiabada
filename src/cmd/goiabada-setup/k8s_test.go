package main

import (
	"bytes"
	"strings"
	"testing"
)

// kubernetesConfig is a Kubernetes answer set in a namespace of its own, with URLs carrying a
// port, a path and a trailing slash, none of which a listener hostname may hold.
func kubernetesConfig() *Config {
	config := goldenConfig(deploymentKubernetes, "postgres")
	config.K8sNamespace = "identity"
	config.AuthServerURL = "https://auth.example.com:8443/"
	config.AdminConsoleURL = "https://admin.example.com/console"
	return config
}

// kubernetesDocuments is the generated manifest's documents by kind and then name.
func kubernetesDocuments(t *testing.T, config *Config) map[string]map[string]map[string]any {
	t.Helper()
	_, content := generatedConfiguration(config)
	byKind := map[string]map[string]map[string]any{}
	for _, doc := range yamlDocuments(t, content) {
		kind := at[string](t, doc, "kind")
		if byKind[kind] == nil {
			byKind[kind] = map[string]map[string]any{}
		}
		byKind[kind][at[string](t, doc, "metadata", "name")] = doc
	}
	return byKind
}

// only is the one element a list must hold.
func only[T any](t *testing.T, list []any, what string) T {
	t.Helper()
	if len(list) != 1 {
		t.Fatalf("%s holds %d entries, want 1: %v", what, len(list), list)
	}
	value, ok := list[0].(T)
	if !ok {
		t.Fatalf("%s is %T", what, list[0])
	}
	return value
}

// The manifest routes through one Gateway and no Ingress: an HTTPS listener per host, each with the
// certificate cert-manager issues for it, and an HTTPRoute per host attached to that host's
// listener and sending it to the Service of the same name on its port (#430).
func TestKubernetesManifest_RoutesEachHostThroughTheGateway(t *testing.T) {
	config := kubernetesConfig()
	docs := kubernetesDocuments(t, config)

	if len(docs["Ingress"]) != 0 {
		t.Fatalf("the manifest still carries Ingresses: %v", docs["Ingress"])
	}
	if len(docs["Gateway"]) != 1 || len(docs["HTTPRoute"]) != 3 {
		t.Fatalf("the manifest has %d Gateways and %d HTTPRoutes, want 1 and 3", len(docs["Gateway"]), len(docs["HTTPRoute"]))
	}
	gateway := docs["Gateway"]["goiabada"]
	if gateway == nil {
		t.Fatal("no Gateway named goiabada")
	}
	if got := at[string](t, gateway, "metadata", "namespace"); got != config.K8sNamespace {
		t.Errorf("the Gateway is in namespace %q, want %q", got, config.K8sNamespace)
	}
	if got := at[string](t, gateway, "metadata", "annotations", "cert-manager.io/cluster-issuer"); got != "letsencrypt-prod" {
		t.Errorf("the Gateway asks cert-manager for issuer %q, want letsencrypt-prod", got)
	}
	if got := at[string](t, gateway, "spec", "gatewayClassName"); got != "eg" {
		t.Errorf("gatewayClassName is %q, want eg", got)
	}

	listeners := map[string]map[string]any{}
	for _, l := range at[[]any](t, gateway, "spec", "listeners") {
		listener := l.(map[string]any)
		listeners[at[string](t, listener, "name")] = listener
	}
	if len(listeners) != 3 {
		t.Fatalf("the Gateway has listeners %v, want http, auth-https and admin-https", listeners)
	}
	http := listeners["http"]
	if at[string](t, http, "protocol") != "HTTP" || at[int](t, http, "port") != 80 {
		t.Errorf("the http listener is %v, want HTTP on 80", http)
	}
	if _, ok := http["hostname"]; ok {
		t.Errorf("the http listener is held to hostname %v, and it serves both hosts", http["hostname"])
	}

	for _, want := range []struct{ listener, host, certificate, service string }{
		{"auth-https", "auth.example.com", "goiabada-tls-auth", "goiabada-authserver"},
		{"admin-https", "admin.example.com", "goiabada-tls-admin", "goiabada-adminconsole"},
	} {
		t.Run(want.listener, func(t *testing.T) {
			listener := listeners[want.listener]
			if listener == nil {
				t.Fatalf("no listener %s", want.listener)
			}
			if at[string](t, listener, "protocol") != "HTTPS" || at[int](t, listener, "port") != 443 {
				t.Errorf("listener %s is %v, want HTTPS on 443", want.listener, listener)
			}
			if got := at[string](t, listener, "hostname"); got != want.host {
				t.Errorf("listener %s has hostname %q, want %q", want.listener, got, want.host)
			}
			if got := at[string](t, listener, "tls", "mode"); got != "Terminate" {
				t.Errorf("listener %s has TLS mode %q, want Terminate", want.listener, got)
			}
			ref := only[map[string]any](t, at[[]any](t, listener, "tls", "certificateRefs"), want.listener+"'s certificateRefs")
			if got := at[string](t, ref, "name"); got != want.certificate {
				t.Errorf("listener %s takes its certificate from %q, want %q", want.listener, got, want.certificate)
			}

			route := docs["HTTPRoute"][want.service]
			if route == nil {
				t.Fatalf("no HTTPRoute named %s", want.service)
			}
			if got := at[string](t, route, "metadata", "namespace"); got != config.K8sNamespace {
				t.Errorf("HTTPRoute %s is in namespace %q, want %q", want.service, got, config.K8sNamespace)
			}
			parent := only[map[string]any](t, at[[]any](t, route, "spec", "parentRefs"), want.service+"'s parentRefs")
			if at[string](t, parent, "name") != "goiabada" || at[string](t, parent, "sectionName") != want.listener {
				t.Errorf("HTTPRoute %s attaches to %v, want the goiabada Gateway's %s", want.service, parent, want.listener)
			}
			if got := only[string](t, at[[]any](t, route, "spec", "hostnames"), want.service+"'s hostnames"); got != want.host {
				t.Errorf("HTTPRoute %s is for %q, want %q", want.service, got, want.host)
			}
			rule := only[map[string]any](t, at[[]any](t, route, "spec", "rules"), want.service+"'s rules")
			backend := only[map[string]any](t, at[[]any](t, rule, "backendRefs"), want.service+"'s backendRefs")
			service := docs["Service"][at[string](t, backend, "name")]
			if service == nil {
				t.Fatalf("HTTPRoute %s sends to %v, which is no Service of the manifest", want.service, backend)
			}
			servicePort := only[map[string]any](t, at[[]any](t, service, "spec", "ports"), "the Service's ports")
			if at[string](t, backend, "name") != want.service || at[int](t, backend, "port") != at[int](t, servicePort, "port") {
				t.Errorf("HTTPRoute %s sends to %v, want %s on port %v", want.service, backend, want.service, servicePort["port"])
			}
		})
	}
}

// Plain HTTP on either host is answered with a permanent redirect to HTTPS, which ingress-nginx did
// by default for a host with TLS (#430).
func TestKubernetesManifest_RedirectsPlainHTTPToHTTPS(t *testing.T) {
	route := kubernetesDocuments(t, kubernetesConfig())["HTTPRoute"]["goiabada-https-redirect"]
	if route == nil {
		t.Fatal("no HTTPRoute named goiabada-https-redirect")
	}
	parent := only[map[string]any](t, at[[]any](t, route, "spec", "parentRefs"), "the redirect's parentRefs")
	if at[string](t, parent, "name") != "goiabada" || at[string](t, parent, "sectionName") != "http" {
		t.Errorf("the redirect attaches to %v, want the goiabada Gateway's http listener", parent)
	}
	hostnames := at[[]any](t, route, "spec", "hostnames")
	if len(hostnames) != 2 || hostnames[0] != "auth.example.com" || hostnames[1] != "admin.example.com" {
		t.Errorf("the redirect is for %v, want both hosts", hostnames)
	}
	rule := only[map[string]any](t, at[[]any](t, route, "spec", "rules"), "the redirect's rules")
	if _, ok := rule["backendRefs"]; ok {
		t.Errorf("the redirect rule also forwards: %v", rule)
	}
	filter := only[map[string]any](t, at[[]any](t, rule, "filters"), "the redirect's filters")
	if got := at[string](t, filter, "type"); got != "RequestRedirect" {
		t.Errorf("the filter is %q, want RequestRedirect", got)
	}
	redirect := at[map[string]any](t, filter, "requestRedirect")
	if at[string](t, redirect, "scheme") != "https" || at[int](t, redirect, "statusCode") != 301 {
		t.Errorf("the redirect is %v, want 301 to https", redirect)
	}
	// With no port, Gateway API has the redirect use https's well-known port, 443.
	if port, ok := redirect["port"]; ok {
		t.Errorf("the redirect names port %v, and https's own is the one wanted", port)
	}
}

// completionYAML is the YAML the completion message asks the operator to save and apply: every
// run of lines from a `---` to the next blank line, less the message's five-space indent.
func completionYAML(t *testing.T, message string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	var block []string
	inBlock := false
	for _, line := range strings.Split(message, "\n") {
		switch {
		case strings.TrimSpace(line) == "---":
			inBlock = true
			block = append(block, "---")
		case inBlock && strings.TrimSpace(line) == "":
			docs = append(docs, yamlDocuments(t, strings.Join(block, "\n"))...)
			block, inBlock = nil, false
		case inBlock:
			if !strings.HasPrefix(line, "     ") {
				t.Fatalf("a line of the message's YAML is not indented by five spaces: %q", line)
			}
			block = append(block, strings.TrimPrefix(line, "     "))
		}
	}
	return docs
}

// The completion message's prerequisites set up exactly what the manifest names: the GatewayClass
// its Gateway asks for, backed by an EnvoyProxy with externalTrafficPolicy Cluster, and the
// ClusterIssuer its annotation asks for, solving HTTP-01 through that Gateway in the manifest's
// namespace. Nothing is left of ingress-nginx, which is retired (#430).
func TestKubernetesInstructions_SetUpWhatTheManifestNames(t *testing.T) {
	config := kubernetesConfig()
	gateway := kubernetesDocuments(t, config)["Gateway"]["goiabada"]
	var buf bytes.Buffer
	printKubernetesInstructions(&console{w: &buf}, config, "goiabada-k8s.yaml")
	message := buf.String()

	for _, gone := range []string{"ingress-nginx", "Ingress", "ingress:", "LoadBalancer"} {
		if strings.Contains(message, gone) {
			t.Errorf("the message still mentions %q", gone)
		}
	}

	byKind := map[string]map[string]any{}
	for _, doc := range completionYAML(t, message) {
		byKind[at[string](t, doc, "kind")] = doc
	}
	if len(byKind) != 3 {
		t.Fatalf("the message's YAML is %d kinds, want EnvoyProxy, GatewayClass and ClusterIssuer", len(byKind))
	}

	class := byKind["GatewayClass"]
	if got, want := at[string](t, class, "metadata", "name"), at[string](t, gateway, "spec", "gatewayClassName"); got != want {
		t.Errorf("the GatewayClass is %q, and the Gateway asks for %q", got, want)
	}
	if got := at[string](t, class, "spec", "controllerName"); got != "gateway.envoyproxy.io/gatewayclass-controller" {
		t.Errorf("the GatewayClass is for controller %q, want Envoy Gateway's", got)
	}
	proxy := byKind["EnvoyProxy"]
	ref := at[map[string]any](t, class, "spec", "parametersRef")
	if at[string](t, ref, "kind") != "EnvoyProxy" || at[string](t, ref, "group") != "gateway.envoyproxy.io" ||
		at[string](t, ref, "name") != at[string](t, proxy, "metadata", "name") ||
		at[string](t, ref, "namespace") != at[string](t, proxy, "metadata", "namespace") {
		t.Errorf("the GatewayClass takes parameters from %v, which is not the EnvoyProxy %v", ref, proxy["metadata"])
	}
	if got := at[string](t, proxy, "spec", "provider", "kubernetes", "envoyService", "externalTrafficPolicy"); got != "Cluster" {
		t.Errorf("the EnvoyProxy sets externalTrafficPolicy %q, want Cluster", got)
	}

	issuer := byKind["ClusterIssuer"]
	if got, want := at[string](t, issuer, "metadata", "name"), at[string](t, gateway, "metadata", "annotations", "cert-manager.io/cluster-issuer"); got != want {
		t.Errorf("the ClusterIssuer is %q, and the Gateway asks for %q", got, want)
	}
	solver := only[map[string]any](t, at[[]any](t, issuer, "spec", "acme", "solvers"), "the issuer's solvers")
	parent := only[map[string]any](t, at[[]any](t, solver, "http01", "gatewayHTTPRoute", "parentRefs"), "the solver's parentRefs")
	if at[string](t, parent, "kind") != "Gateway" || at[string](t, parent, "name") != at[string](t, gateway, "metadata", "name") ||
		at[string](t, parent, "namespace") != config.K8sNamespace {
		t.Errorf("the solver attaches to %v, want the Gateway %s in %s", parent, gateway["metadata"], config.K8sNamespace)
	}

	for _, command := range []string{
		"kubectl get gateway goiabada -n identity -o jsonpath='{.status.addresses[0].value}'",
		"kubectl get gateway,httproute -n identity",
	} {
		if !strings.Contains(message, command) {
			t.Errorf("the message has no %q", command)
		}
	}
}

// Each container is held for five seconds before it is signalled, through Kubernetes' own sleep
// action, so the gateway learns the pod is going before the server closes its listener; and each
// pod's grace period is 65 seconds, the auth server's 50-second stop with 10 seconds of headroom
// plus that pause, which counts against it (#390 decisions 2 and 4).
func TestKubernetesManifest_GivesEachContainerTimeToStop(t *testing.T) {
	deployments := kubernetesDocuments(t, kubernetesConfig())["Deployment"]
	for _, name := range []string{"goiabada-authserver", "goiabada-adminconsole"} {
		t.Run(name, func(t *testing.T) {
			deployment := deployments[name]
			if deployment == nil {
				t.Fatalf("no Deployment named %s", name)
			}
			podSpec := at[map[string]any](t, deployment, "spec", "template", "spec")
			if got := at[int](t, podSpec, "terminationGracePeriodSeconds"); got != 65 {
				t.Errorf("terminationGracePeriodSeconds is %d, want 65", got)
			}
			container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), name+"'s containers")
			preStop := at[map[string]any](t, container, "lifecycle", "preStop")
			if len(preStop) != 1 {
				t.Errorf("the preStop hook is %v, want the sleep action alone", preStop)
			}
			if got := at[int](t, preStop, "sleep", "seconds"); got != 5 {
				t.Errorf("the preStop sleep is %d seconds, want 5", got)
			}
		})
	}
}

// Each container is given five minutes to start, through a startup probe on /health every five
// seconds with sixty failures allowed, and liveness and readiness are held off until it succeeds
// rather than by an initial delay, so a first start that seeds or an upgrade that migrates is not
// killed at about 40 seconds. Every probe states its period, timeout and failure threshold, liveness
// and readiness at the values Kubernetes applied before (#390, the probe assumptions).
func TestKubernetesManifest_GatesEachContainerOnAStartupProbe(t *testing.T) {
	deployments := kubernetesDocuments(t, kubernetesConfig())["Deployment"]
	for _, want := range []struct {
		deployment string
		port       int
	}{
		{"goiabada-authserver", 9090},
		{"goiabada-adminconsole", 9091},
	} {
		t.Run(want.deployment, func(t *testing.T) {
			deployment := deployments[want.deployment]
			if deployment == nil {
				t.Fatalf("no Deployment named %s", want.deployment)
			}
			podSpec := at[map[string]any](t, deployment, "spec", "template", "spec")
			container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), want.deployment+"'s containers")
			for _, probe := range []struct {
				name                              string
				period, timeout, failureThreshold int
			}{
				{"startupProbe", 5, 1, 60},
				{"livenessProbe", 10, 1, 3},
				{"readinessProbe", 5, 1, 3},
			} {
				t.Run(probe.name, func(t *testing.T) {
					spec := at[map[string]any](t, container, probe.name)
					if got := at[string](t, spec, "httpGet", "path"); got != "/health" {
						t.Errorf("%s asks for %q, want /health", probe.name, got)
					}
					if got := at[int](t, spec, "httpGet", "port"); got != want.port {
						t.Errorf("%s asks port %d, want %d", probe.name, got, want.port)
					}
					if _, ok := spec["initialDelaySeconds"]; ok {
						t.Errorf("%s waits initialDelaySeconds %v, and the startup probe is what holds it off", probe.name, spec["initialDelaySeconds"])
					}
					if got := at[int](t, spec, "periodSeconds"); got != probe.period {
						t.Errorf("%s has periodSeconds %d, want %d", probe.name, got, probe.period)
					}
					if got := at[int](t, spec, "timeoutSeconds"); got != probe.timeout {
						t.Errorf("%s has timeoutSeconds %d, want %d", probe.name, got, probe.timeout)
					}
					if got := at[int](t, spec, "failureThreshold"); got != probe.failureThreshold {
						t.Errorf("%s has failureThreshold %d, want %d", probe.name, got, probe.failureThreshold)
					}
				})
			}
		})
	}
}
