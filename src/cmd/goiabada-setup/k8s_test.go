package main

import (
	"bytes"
	"maps"
	"reflect"
	"slices"
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

// kubernetesDocuments is the documents of the generated manifest and its secrets file, by kind and
// then name.
func kubernetesDocuments(t *testing.T, config *Config) map[string]map[string]map[string]any {
	t.Helper()
	description, secrets := generatedConfiguration(config)
	docs := yamlDocuments(t, description.content)
	if secrets != description {
		docs = append(docs, yamlDocuments(t, secrets.content)...)
	}
	byKind := map[string]map[string]map[string]any{}
	for _, doc := range docs {
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
// its Gateway asks for, backed by an EnvoyProxy with the traffic policy the operator chose, and the
// ClusterIssuer its annotation asks for, solving HTTP-01 through that Gateway in the manifest's
// namespace. Nothing is left of ingress-nginx, which is retired (#430). Under Local, Envoy runs on
// every node as a DaemonSet, so no node the load balancer sends to drops the traffic; under Cluster
// it stays a Deployment (#396 decision 4, checked against Envoy Gateway v1.9.1's API types).
func TestKubernetesInstructions_SetUpWhatTheManifestNames(t *testing.T) {
	for _, policy := range []trafficPolicy{trafficPolicyCluster, trafficPolicyLocal} {
		t.Run(string(policy), func(t *testing.T) {
			config := kubernetesConfig()
			config.GatewayTrafficPolicy = policy
			gateway := kubernetesDocuments(t, config)["Gateway"]["goiabada"]
			var buf bytes.Buffer
			printKubernetesInstructions(&console{w: &buf}, config, outputPaths{"goiabada-k8s.yaml", "goiabada-secrets.yaml"})
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
			provider := at[map[string]any](t, proxy, "spec", "provider", "kubernetes")
			if got := at[string](t, provider, "envoyService", "externalTrafficPolicy"); got != string(policy) {
				t.Errorf("the EnvoyProxy sets externalTrafficPolicy %q, want %s", got, policy)
			}
			// Envoy Gateway v1.9.1 admits one of envoyDeployment and envoyDaemonSet, and an empty
			// envoyDaemonSet is a DaemonSet with every default.
			if _, ok := provider["envoyDeployment"]; ok {
				t.Errorf("the EnvoyProxy sets envoyDeployment: %v", provider["envoyDeployment"])
			}
			daemonSet, isDaemonSet := provider["envoyDaemonSet"]
			if want := policy == trafficPolicyLocal; isDaemonSet != want {
				t.Errorf("the EnvoyProxy runs Envoy as a DaemonSet: %v, want %v", isDaemonSet, want)
			}
			if isDaemonSet {
				if spec, ok := daemonSet.(map[string]any); !ok || len(spec) != 0 {
					t.Errorf("envoyDaemonSet is %v, want an empty mapping", daemonSet)
				}
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
		})
	}
}

// The EnvoyProxy and the GatewayClass are cluster-wide, so the message says the traffic policy is
// the choice of whoever runs Envoy Gateway; and its troubleshooting tips follow the policy chosen:
// under Cluster, the EnvoyProxy that sets it, and under Local, the DaemonSet that must run an Envoy
// pod on every node the load balancer sends to (#396 decision 4).
func TestKubernetesInstructions_FollowTheTrafficPolicy(t *testing.T) {
	for _, testCase := range []struct {
		policy          trafficPolicy
		wanted, refused []string
	}{
		{trafficPolicyCluster,
			[]string{"If the GatewayClass has no EnvoyProxy with externalTrafficPolicy: Cluster"},
			[]string{"kubectl get daemonset -n envoy-gateway-system"}},
		{trafficPolicyLocal,
			[]string{"kubectl get daemonset -n envoy-gateway-system", "--gateway-traffic-policy=cluster"},
			[]string{"If the GatewayClass has no EnvoyProxy with externalTrafficPolicy: Cluster"}},
	} {
		t.Run(string(testCase.policy), func(t *testing.T) {
			config := kubernetesConfig()
			config.GatewayTrafficPolicy = testCase.policy
			var buf bytes.Buffer
			printKubernetesInstructions(&console{w: &buf}, config, outputPaths{"goiabada-k8s.yaml", "goiabada-secrets.yaml"})
			message := buf.String()
			if !strings.Contains(message, "cluster-wide") || !strings.Contains(message, "whoever runs") {
				t.Errorf("the message does not say the EnvoyProxy and GatewayClass are cluster-wide, so the choice is whoever runs Envoy Gateway's:\n%s", message)
			}
			tips := message[strings.Index(message, "TROUBLESHOOTING TIPS"):]
			for _, want := range testCase.wanted {
				if !strings.Contains(tips, want) {
					t.Errorf("the troubleshooting tips lack %q:\n%s", want, tips)
				}
			}
			for _, refused := range testCase.refused {
				if strings.Contains(message, refused) {
					t.Errorf("the message says %q under %s", refused, testCase.policy)
				}
			}
		})
	}
}

// Both ConfigMaps say, beside the trust they set, which address the servers see under the traffic
// policy chosen: a node's under Cluster, where Envoy receives each connection from a node, and the
// client's under Local, where it receives it from the client itself (#396 decision 4).
func TestKubernetesManifest_SaysWhichAddressTheServersSee(t *testing.T) {
	for _, testCase := range []struct {
		policy       trafficPolicy
		said, unsaid string
	}{
		{trafficPolicyCluster, "a node's address", "the client's address"},
		{trafficPolicyLocal, "the client's address", "a node's address"},
	} {
		t.Run(string(testCase.policy), func(t *testing.T) {
			config := kubernetesConfig()
			config.GatewayTrafficPolicy = testCase.policy
			content := descriptionOf(config)
			lines := strings.Split(content, "\n")
			checked := 0
			for i, line := range lines {
				if !strings.Contains(line, "_TRUST_PROXY_HEADERS:") {
					continue
				}
				comment := commentAbove(lines, i)
				if !strings.Contains(comment, testCase.said) || !strings.Contains(comment, string(testCase.policy)) {
					t.Errorf("line %d's comment does not say the servers see %s under %s: %q", i+1, testCase.said, testCase.policy, comment)
				}
				if strings.Contains(comment, testCase.unsaid) {
					t.Errorf("line %d's comment says the servers see %s under %s: %q", i+1, testCase.unsaid, testCase.policy, comment)
				}
				checked++
			}
			if checked != 2 {
				t.Fatalf("%d lines set TRUST_PROXY_HEADERS, want one per ConfigMap", checked)
			}
		})
	}
}

// networkPolicyComment is the block of comment lines directly above the NetworkPolicy's document,
// between its `---` and its apiVersion.
func networkPolicyComment(t *testing.T, content, name string) string {
	t.Helper()
	for _, doc := range strings.Split(content, "\n---\n") {
		if !strings.Contains(doc, "\nkind: NetworkPolicy\n") || !strings.Contains(doc, "\n  name: "+name+"\n") {
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
	t.Fatalf("no NetworkPolicy document named %s", name)
	return ""
}

// On yes, each Deployment gets an ingress-only NetworkPolicy: the auth server's pods admit 9090 from
// the Envoy proxies' namespace and from the admin console's pods, the admin console's admit 9091
// from the Envoy proxies' namespace alone, and neither states an egress rule, since the SMTP server
// and the database host are nothing a NetworkPolicy can select. Each comment says why there is no
// egress rule, that only a CNI that implements NetworkPolicy enforces it, and how to admit another
// namespace. On no, nothing is emitted (#396 decision 5).
func TestKubernetesManifest_AdmitsOnlyEnvoyWhenAsked(t *testing.T) {
	envoy := map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "envoy-gateway-system"}}}
	adminConsole := map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "goiabada-adminconsole"}}}
	// The auth server's comment carries the reasons and the recipe; the admin console's, whose
	// pods nothing in the cluster calls, says it is ingress-only and where it is enforced.
	want := map[string]struct {
		port    int
		from    []any
		comment []string
	}{
		"goiabada-authserver":   {9090, []any{envoy, adminConsole}, []string{"egress", "SMTP", "database", "CNI", "kubernetes.io/metadata.name: <"}},
		"goiabada-adminconsole": {9091, []any{envoy}, []string{"egress", "CNI"}},
	}

	t.Run("no", func(t *testing.T) {
		config := kubernetesConfig()
		if policies := kubernetesDocuments(t, config)["NetworkPolicy"]; len(policies) != 0 {
			t.Errorf("the manifest carries NetworkPolicies %v when none was asked for", slices.Sorted(maps.Keys(policies)))
		}
	})
	t.Run("yes", func(t *testing.T) {
		config := kubernetesConfig()
		config.NetworkPolicy = true
		docs := kubernetesDocuments(t, config)
		content := descriptionOf(config)
		if len(docs["NetworkPolicy"]) != len(workloads) {
			t.Errorf("the manifest has NetworkPolicies %v, want one per Deployment", slices.Sorted(maps.Keys(docs["NetworkPolicy"])))
		}
		for _, w := range workloads {
			t.Run(w.deployment, func(t *testing.T) {
				policy := docs["NetworkPolicy"][w.deployment]
				if policy == nil {
					t.Fatalf("no NetworkPolicy named %s", w.deployment)
				}
				if got := at[string](t, policy, "apiVersion"); got != "networking.k8s.io/v1" {
					t.Errorf("apiVersion is %q, want networking.k8s.io/v1", got)
				}
				if got := at[string](t, policy, "metadata", "namespace"); got != config.K8sNamespace {
					t.Errorf("the policy is in namespace %q, want %q", got, config.K8sNamespace)
				}
				spec := at[map[string]any](t, policy, "spec")
				selector := at[map[string]any](t, spec, "podSelector", "matchLabels")
				pods := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "metadata", "labels")
				if len(selector) != 1 || selector["app"] != w.deployment || pods["app"] != w.deployment {
					t.Errorf("the policy selects %v, and the Deployment's pods are %v", selector, pods)
				}
				if got := only[string](t, at[[]any](t, spec, "policyTypes"), "policyTypes"); got != "Ingress" {
					t.Errorf("policyTypes is %q, want Ingress alone", got)
				}
				if egress, ok := spec["egress"]; ok {
					t.Errorf("the policy states egress rules %v", egress)
				}
				rule := only[map[string]any](t, at[[]any](t, spec, "ingress"), "the ingress rules")
				port := only[map[string]any](t, at[[]any](t, rule, "ports"), "the rule's ports")
				if at[string](t, port, "protocol") != "TCP" || at[int](t, port, "port") != want[w.deployment].port {
					t.Errorf("the rule admits %v, want TCP %d", port, want[w.deployment].port)
				}
				if got := at[[]any](t, rule, "from"); !reflect.DeepEqual(got, want[w.deployment].from) {
					t.Errorf("the rule admits %v, want %v", got, want[w.deployment].from)
				}

				comment := networkPolicyComment(t, content, w.deployment)
				for _, said := range want[w.deployment].comment {
					if !strings.Contains(comment, said) {
						t.Errorf("the policy's comment does not mention %q: %q", said, comment)
					}
				}
			})
		}
	})
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

// workloads are the manifest's two Deployments, the container each runs, and the ConfigMap each
// reads, by Deployment name.
var workloads = []struct{ deployment, container, configMap string }{
	{"goiabada-authserver", "authserver", "goiabada-authserver-config"},
	{"goiabada-adminconsole", "adminconsole", "goiabada-adminconsole-config"},
}

// deploymentNamed is the manifest's Deployment of that name, failing the test when there is none.
func deploymentNamed(t *testing.T, docs map[string]map[string]map[string]any, name string) map[string]any {
	t.Helper()
	deployment := docs["Deployment"][name]
	if deployment == nil {
		t.Fatalf("no Deployment named %s", name)
	}
	return deployment
}

// Each container states every field the restricted Pod Security Standard requires, and a read-only
// root besides, on its own securityContext with no pod-level one beside it; each pod mounts no
// service account token and is handed no service links, since neither binary calls the Kubernetes
// API or reads the variables Kubernetes would inject (#396 decision 2, the service-link assumption).
func TestKubernetesManifest_HardensEveryContainerToTheRestrictedStandard(t *testing.T) {
	docs := kubernetesDocuments(t, kubernetesConfig())
	for _, w := range workloads {
		t.Run(w.deployment, func(t *testing.T) {
			podSpec := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec")
			if got := at[bool](t, podSpec, "automountServiceAccountToken"); got {
				t.Errorf("automountServiceAccountToken is %v, want false", got)
			}
			if got := at[bool](t, podSpec, "enableServiceLinks"); got {
				t.Errorf("enableServiceLinks is %v, want false", got)
			}
			if context, ok := podSpec["securityContext"]; ok {
				t.Errorf("the pod carries a securityContext %v, and each container states its own", context)
			}

			container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), w.deployment+"'s containers")
			if got := at[string](t, container, "name"); got != w.container {
				t.Fatalf("the container is %q, want %q", got, w.container)
			}
			context := at[map[string]any](t, container, "securityContext")
			for _, field := range []struct {
				path []string
				want any
			}{
				{[]string{"runAsNonRoot"}, true},
				{[]string{"runAsUser"}, 10001},
				{[]string{"runAsGroup"}, 10001},
				{[]string{"allowPrivilegeEscalation"}, false},
				{[]string{"readOnlyRootFilesystem"}, true},
				{[]string{"seccompProfile", "type"}, "RuntimeDefault"},
			} {
				if got := at[any](t, context, field.path...); got != field.want {
					t.Errorf("securityContext.%s is %v, want %v", strings.Join(field.path, "."), got, field.want)
				}
			}
			if got := only[string](t, at[[]any](t, context, "capabilities", "drop"), "the dropped capabilities"); got != "ALL" {
				t.Errorf("the container drops %q, want ALL", got)
			}
			if add, ok := at[map[string]any](t, context, "capabilities")["add"]; ok {
				t.Errorf("the container adds capabilities %v", add)
			}
			if mounts, ok := container["volumeMounts"]; ok {
				t.Errorf("the container mounts %v, and neither binary writes to its filesystem", mounts)
			}
		})
	}
}

// The Namespace warns and audits at restricted, so every apply reports a pod that breaks the
// standard, and enforces nothing, since the wizard accepts a namespace someone else's workloads may
// already run in (#396 decision 20).
func TestKubernetesManifest_LabelsTheNamespaceToWarnAndAuditAtRestricted(t *testing.T) {
	config := kubernetesConfig()
	namespace := kubernetesDocuments(t, config)["Namespace"][config.K8sNamespace]
	if namespace == nil {
		t.Fatalf("no Namespace named %s", config.K8sNamespace)
	}
	labels := at[map[string]any](t, namespace, "metadata", "labels")
	for _, mode := range []string{"warn", "audit"} {
		if got := at[string](t, labels, "pod-security.kubernetes.io/"+mode); got != "restricted" {
			t.Errorf("pod-security.kubernetes.io/%s is %q, want restricted", mode, got)
		}
	}
	if enforce, ok := labels["pod-security.kubernetes.io/enforce"]; ok {
		t.Errorf("the Namespace enforces %v, and it may hold workloads that are not Goiabada's", enforce)
	}
}

// Each Deployment rolls out by starting one new pod before it stops an old one, never running
// fewer than its replicas, the surge pod the docs' connection arithmetic counts (#396 assumptions).
func TestKubernetesManifest_RollsOutOnePodAtATimeWithNoneUnavailable(t *testing.T) {
	docs := kubernetesDocuments(t, kubernetesConfig())
	for _, w := range workloads {
		t.Run(w.deployment, func(t *testing.T) {
			strategy := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "strategy")
			if got := at[string](t, strategy, "type"); got != "RollingUpdate" {
				t.Errorf("the strategy is %q, want RollingUpdate", got)
			}
			if got := at[int](t, strategy, "rollingUpdate", "maxUnavailable"); got != 0 {
				t.Errorf("maxUnavailable is %d, want 0", got)
			}
			if got := at[int](t, strategy, "rollingUpdate", "maxSurge"); got != 1 {
				t.Errorf("maxSurge is %d, want 1", got)
			}
		})
	}
}

// Each Deployment has a PodDisruptionBudget allowing one of its pods to be evicted at a time,
// selecting exactly the pods the Deployment runs, in the manifest's namespace (#396 assumptions).
func TestKubernetesManifest_GivesEachDeploymentADisruptionBudget(t *testing.T) {
	config := kubernetesConfig()
	docs := kubernetesDocuments(t, config)
	if len(docs["PodDisruptionBudget"]) != len(workloads) {
		t.Errorf("the manifest has %d PodDisruptionBudgets, want one per Deployment", len(docs["PodDisruptionBudget"]))
	}
	for _, w := range workloads {
		t.Run(w.deployment, func(t *testing.T) {
			deployment := deploymentNamed(t, docs, w.deployment)
			budget := docs["PodDisruptionBudget"][w.deployment]
			if budget == nil {
				t.Fatalf("no PodDisruptionBudget named %s", w.deployment)
			}
			if got := at[string](t, budget, "apiVersion"); got != "policy/v1" {
				t.Errorf("the budget's apiVersion is %q, want policy/v1", got)
			}
			if got := at[string](t, budget, "metadata", "namespace"); got != config.K8sNamespace {
				t.Errorf("the budget is in namespace %q, want %q", got, config.K8sNamespace)
			}
			if got := at[int](t, budget, "spec", "maxUnavailable"); got != 1 {
				t.Errorf("the budget's maxUnavailable is %d, want 1", got)
			}
			if minAvailable, ok := at[map[string]any](t, budget, "spec")["minAvailable"]; ok {
				t.Errorf("the budget also sets minAvailable %v", minAvailable)
			}
			selector := at[map[string]any](t, budget, "spec", "selector", "matchLabels")
			want := at[map[string]any](t, deployment, "spec", "selector", "matchLabels")
			if len(selector) != 1 || selector["app"] != w.deployment || selector["app"] != want["app"] || len(want) != 1 {
				t.Errorf("the budget selects %v, and the Deployment's pods are %v", selector, want)
			}
		})
	}
}

// Each Deployment spreads its pods over nodes, one apart at most, preferring the spread rather than
// refusing to schedule: inert at one replica, and at three it keeps a drain from taking them all
// (#396 assumptions).
func TestKubernetesManifest_SpreadsEachDeploymentOverNodes(t *testing.T) {
	docs := kubernetesDocuments(t, kubernetesConfig())
	for _, w := range workloads {
		t.Run(w.deployment, func(t *testing.T) {
			template := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template")
			constraint := only[map[string]any](t, at[[]any](t, template, "spec", "topologySpreadConstraints"), "the spread constraints")
			if got := at[int](t, constraint, "maxSkew"); got != 1 {
				t.Errorf("maxSkew is %d, want 1", got)
			}
			if got := at[string](t, constraint, "topologyKey"); got != "kubernetes.io/hostname" {
				t.Errorf("topologyKey is %q, want kubernetes.io/hostname", got)
			}
			if got := at[string](t, constraint, "whenUnsatisfiable"); got != "ScheduleAnyway" {
				t.Errorf("whenUnsatisfiable is %q, want ScheduleAnyway", got)
			}
			selector := at[map[string]any](t, constraint, "labelSelector", "matchLabels")
			labels := at[map[string]any](t, template, "metadata", "labels")
			if len(selector) != 1 || selector["app"] != w.deployment || labels["app"] != w.deployment {
				t.Errorf("the spread counts pods %v, and the Deployment's pods are %v", selector, labels)
			}
		})
	}
}

// withImageTag runs the test with the image tag a release build stamps, putting the source build's
// back afterwards.
func withImageTag(t *testing.T, tag string) {
	t.Helper()
	previous := imageTag
	imageTag = tag
	t.Cleanup(func() { imageTag = previous })
}

// A version tag names one build, so a node pulls it once; a source build's latest moves, so a node
// pulls it at every start, or it would run whichever latest it happened to cache (#396 decision 10).
func TestKubernetesManifest_PullPolicyFollowsTheTag(t *testing.T) {
	for _, testCase := range []struct{ tag, policy string }{
		{"latest", "Always"},
		{"1.5.0", "IfNotPresent"},
		{"2.0.0-rc.1", "IfNotPresent"},
	} {
		t.Run(testCase.tag, func(t *testing.T) {
			withImageTag(t, testCase.tag)
			docs := kubernetesDocuments(t, kubernetesConfig())
			for _, w := range workloads {
				podSpec := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec")
				container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), w.deployment+"'s containers")
				if got, want := at[string](t, container, "image"), "leodip/goiabada:"+w.container+"-"+testCase.tag; got != want {
					t.Errorf("%s runs %q, want %q", w.deployment, got, want)
				}
				if got := at[string](t, container, "imagePullPolicy"); got != testCase.policy {
					t.Errorf("%s pulls %s, want %s", w.deployment, got, testCase.policy)
				}
			}
		})
	}
}

// A source build's manifest follows a moving tag, and the completion message says so; a release
// build's names its version, and the message has nothing to warn about (#396 decision 10).
func TestKubernetesInstructions_WarnWhenTheManifestFollowsAMovingTag(t *testing.T) {
	const warning = "follows the moving image tag"
	for _, testCase := range []struct {
		tag  string
		warn bool
	}{
		{"latest", true},
		{"1.5.0", false},
		{"2.0.0-rc.1", false},
	} {
		t.Run(testCase.tag, func(t *testing.T) {
			withImageTag(t, testCase.tag)
			var buf bytes.Buffer
			printKubernetesInstructions(&console{w: &buf}, kubernetesConfig(), outputPaths{"goiabada-k8s.yaml", "goiabada-secrets.yaml"})
			message := buf.String()
			if got := strings.Contains(message, warning); got != testCase.warn {
				t.Errorf("the message warns %q: %v, want %v\n%s", warning, got, testCase.warn, message)
			}
			if testCase.warn && !strings.Contains(message, "Warning:") {
				t.Errorf("the moving tag is not reported as a warning:\n%s", message)
			}
		})
	}
}

// Each process reads a ConfigMap of its own holding exactly the variables it reads, the three URLs
// in both and the same in both; nothing reads the shared goiabada-config any more (#396 decision 13).
// What each server reads is held from its own unit tier, against the goldens; this is the list.
func TestKubernetesManifest_GivesEachProcessAConfigMapOfItsOwn(t *testing.T) {
	config := kubernetesConfig()
	docs := kubernetesDocuments(t, config)
	if len(docs["ConfigMap"]) != 2 {
		t.Errorf("the manifest has ConfigMaps %v, want the auth server's and the admin console's", slices.Sorted(maps.Keys(docs["ConfigMap"])))
	}

	urls := map[string]string{
		"GOIABADA_AUTHSERVER_BASEURL":         config.AuthServerURL,
		"GOIABADA_AUTHSERVER_INTERNALBASEURL": "http://goiabada-authserver:9090",
		"GOIABADA_ADMINCONSOLE_BASEURL":       config.AdminConsoleURL,
	}
	wantKeys := map[string][]string{
		"goiabada-authserver-config": {
			"GOIABADA_ADMINCONSOLE_BASEURL",
			"GOIABADA_ADMIN_EMAIL",
			"GOIABADA_APPNAME",
			"GOIABADA_AUTHSERVER_BASEURL",
			"GOIABADA_AUTHSERVER_INTERNALBASEURL",
			"GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS",
			"GOIABADA_AUTHSERVER_RATELIMITER_ENABLED",
			"GOIABADA_AUTHSERVER_TRUSTED_PROXIES",
			"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS",
			"GOIABADA_DB_HOST",
			"GOIABADA_DB_NAME",
			"GOIABADA_DB_PORT",
			"GOIABADA_DB_TYPE",
			"GOIABADA_DB_USERNAME",
		},
		"goiabada-adminconsole-config": {
			"GOIABADA_ADMINCONSOLE_BASEURL",
			"GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS",
			"GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES",
			"GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS",
			"GOIABADA_AUTHSERVER_BASEURL",
			"GOIABADA_AUTHSERVER_INTERNALBASEURL",
		},
	}
	for _, w := range workloads {
		t.Run(w.deployment, func(t *testing.T) {
			configMap := docs["ConfigMap"][w.configMap]
			if configMap == nil {
				t.Fatalf("no ConfigMap named %s", w.configMap)
			}
			if got := at[string](t, configMap, "metadata", "namespace"); got != config.K8sNamespace {
				t.Errorf("%s is in namespace %q, want %q", w.configMap, got, config.K8sNamespace)
			}
			data := at[map[string]any](t, configMap, "data")
			if got := slices.Sorted(maps.Keys(data)); !slices.Equal(got, wantKeys[w.configMap]) {
				t.Errorf("%s holds %v, want %v", w.configMap, got, wantKeys[w.configMap])
			}
			for name, want := range urls {
				if got := at[string](t, data, name); got != want {
					t.Errorf("%s sets %s to %q, want %q", w.configMap, name, got, want)
				}
			}

			podSpec := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec")
			container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), w.deployment+"'s containers")
			source := only[map[string]any](t, at[[]any](t, container, "envFrom"), w.deployment+"'s envFrom")
			if got := at[string](t, source, "configMapRef", "name"); got != w.configMap {
				t.Errorf("%s reads the ConfigMap %q, want %q", w.deployment, got, w.configMap)
			}
		})
	}
}
