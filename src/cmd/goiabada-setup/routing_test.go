package main

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The routing step's prompts, as the scripted prompter reads them.
const (
	tlsPrompt          = "Select certificates [1-4] [1]: "
	gatewayClassPrompt = "GatewayClass of the Gateway: "
	httpPortPrompt     = "HTTP listener port [80]: "
	httpsPortPrompt    = "HTTPS listener port [443]: "
	ingressClassPrompt = "IngressClass, blank for the cluster's default class: "
)

// routingScript is the interactive Kubernetes script answering the routing question with choice, a
// mode other than the Envoy Gateway recipe, followed by the steps that mode asks in place of the
// traffic policy, which only the recipe asks.
func routingScript(t *testing.T, choice string, followUps ...scriptedStep) []scriptedStep {
	t.Helper()
	steps := withAnswers(t, deploymentKubernetes, map[string]string{routingPrompt: choice})
	at := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == routingPrompt })
	if steps[at+1].prompt != trafficPolicyPrompt {
		t.Fatalf("the script does not ask the traffic policy after the routing: %q", steps[at+1].prompt)
	}
	steps = slices.Delete(steps, at+1, at+2)
	return slices.Insert(steps, at+1, followUps...)
}

// writtenDocuments is the manifest the wizard wrote, its documents by kind and name.
func writtenDocuments(t *testing.T, w *wizard) map[string]map[string]map[string]any {
	t.Helper()
	written, err := os.ReadFile(w.paths.description)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]map[string]map[string]any{}
	for _, doc := range yamlDocuments(t, string(written)) {
		kind, _ := doc["kind"].(string)
		metadata, _ := doc["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if docs[kind] == nil {
			docs[kind] = map[string]map[string]any{}
		}
		docs[kind][name] = doc
	}
	return docs
}

// routingAnswers are the Config's routing answers, the Secrets' names only when the platform
// supplies them.
type routingAnswers struct {
	Routing                                  routing
	GatewayClass                             string
	GatewayHTTPPort, GatewayHTTPSPort        int
	GatewayName, GatewayNamespace            string
	AuthListener, AdminListener              string
	IngressClass                             string
	TLS                                      tlsSource
	TLSIssuer, TLSSecretAuth, TLSSecretAdmin string
}

func routingAnswersOf(c *Config) routingAnswers {
	answers := routingAnswers{c.Routing, c.GatewayClass, c.GatewayHTTPPort, c.GatewayHTTPSPort, c.GatewayName, c.GatewayNamespace,
		c.AuthListener, c.AdminListener, c.IngressClass, c.TLS, c.TLSIssuer, "", ""}
	if c.TLS == tlsSecrets {
		answers.TLSSecretAuth, answers.TLSSecretAdmin = c.TLSSecretAuth, c.TLSSecretAdmin
	}
	return answers
}

// Kubernetes asks how traffic reaches the servers, the Envoy Gateway recipe by default, and what the
// mode chosen attaches to; --routing and the mode's flags answer without a prompt, and a name the
// mode needs is required. The answer is what the manifest routes with (#686 section 3).
func TestWizard_KubernetesAsksHowTrafficReachesIt(t *testing.T) {
	flags := func(change func(f *CLIFlags)) *CLIFlags {
		f := kubernetesFlags()
		change(f)
		return f
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  routingAnswers
		// kinds is how many objects of each routing kind the manifest writes.
		kinds map[string]int
	}{
		"prompted, the default": {&CLIFlags{}, withAnswers(t, deploymentKubernetes, map[string]string{routingPrompt: ""}),
			routingAnswers{Routing: routingEnvoyGateway, GatewayClass: "eg", GatewayHTTPPort: 80, GatewayHTTPSPort: 443, TLS: tlsClusterIssuer, TLSIssuer: letsEncryptIssuer},
			map[string]int{"Gateway": 1, "HTTPRoute": 3}},
		"prompted, a Gateway of the cluster's class": {&CLIFlags{}, routingScript(t, "2",
			scriptedStep{prompt: gatewayClassPrompt, answer: "Traefik"},
			scriptedStep{prompt: gatewayClassPrompt, answer: "traefik"},
			scriptedStep{prompt: tlsPrompt, answer: ""},
			scriptedStep{prompt: "ClusterIssuer name: ", answer: "internal-ca"},
			scriptedStep{prompt: httpPortPrompt, answer: "8000"},
			scriptedStep{prompt: httpsPortPrompt, answer: "8000"},
			scriptedStep{prompt: httpPortPrompt, answer: "8000"},
			scriptedStep{prompt: httpsPortPrompt, answer: "8443"},
		), routingAnswers{Routing: routingGateway, GatewayClass: "traefik", GatewayHTTPPort: 8000, GatewayHTTPSPort: 8443, TLS: tlsClusterIssuer, TLSIssuer: "internal-ca"},
			map[string]int{"Gateway": 1, "HTTPRoute": 3}},
		"prompted, a Gateway behind TLS ended in front": {&CLIFlags{}, routingScript(t, "2",
			scriptedStep{prompt: gatewayClassPrompt, answer: "eg"},
			scriptedStep{prompt: tlsPrompt, answer: "4"},
			scriptedStep{prompt: httpPortPrompt, answer: ""},
		), routingAnswers{Routing: routingGateway, GatewayClass: "eg", GatewayHTTPPort: 80, TLS: tlsExternal},
			map[string]int{"Gateway": 1, "HTTPRoute": 2}},
		"prompted, someone else's Gateway": {&CLIFlags{}, routingScript(t, "3",
			scriptedStep{prompt: "Gateway name: ", answer: "shared"},
			scriptedStep{prompt: "Gateway namespace: ", answer: "infra"},
			scriptedStep{prompt: "HTTPS listener for auth.example.org: ", answer: "https"},
			scriptedStep{prompt: "HTTPS listener for admin.example.org [https]: ", answer: ""},
		), routingAnswers{Routing: routingExistingGateway, GatewayName: "shared", GatewayNamespace: "infra", AuthListener: "https", AdminListener: "https"},
			map[string]int{"HTTPRoute": 2}},
		"prompted, Ingresses with Secrets": {&CLIFlags{}, routingScript(t, "4",
			scriptedStep{prompt: ingressClassPrompt, answer: ""},
			scriptedStep{prompt: tlsPrompt, answer: "3"},
			scriptedStep{prompt: "TLS Secret for auth.example.org [goiabada-tls-auth]: ", answer: "wildcard"},
			scriptedStep{prompt: "TLS Secret for admin.example.org [goiabada-tls-admin]: ", answer: "wildcard"},
		), routingAnswers{Routing: routingIngress, TLS: tlsSecrets, TLSSecretAuth: "wildcard", TLSSecretAdmin: "wildcard"},
			map[string]int{"Ingress": 2}},
		"prompted, none": {&CLIFlags{}, routingScript(t, "5"), routingAnswers{Routing: routingNone}, map[string]int{}},
		"by flag, left out": {kubernetesFlags(), nil,
			routingAnswers{Routing: routingEnvoyGateway, GatewayClass: "eg", GatewayHTTPPort: 80, GatewayHTTPSPort: 443, TLS: tlsClusterIssuer, TLSIssuer: letsEncryptIssuer},
			map[string]int{"Gateway": 1, "HTTPRoute": 3}},
		"by flag, a Gateway with every default": {flags(func(f *CLIFlags) {
			f.Routing, f.GatewayClass, f.TLSIssuer = routingGateway, "cilium", "corp-ca"
		}), nil, routingAnswers{Routing: routingGateway, GatewayClass: "cilium", GatewayHTTPPort: 80, GatewayHTTPSPort: 443, TLS: tlsClusterIssuer, TLSIssuer: "corp-ca"},
			map[string]int{"Gateway": 1, "HTTPRoute": 3}},
		"by flag, someone else's Gateway, one listener": {flags(func(f *CLIFlags) {
			f.Routing, f.GatewayName, f.GatewayNamespace, f.AuthListener = routingExistingGateway, "shared", "infra", "https"
		}), nil, routingAnswers{Routing: routingExistingGateway, GatewayName: "shared", GatewayNamespace: "infra", AuthListener: "https", AdminListener: "https"},
			map[string]int{"HTTPRoute": 2}},
		"by flag, Ingresses from an Issuer": {flags(func(f *CLIFlags) {
			f.Routing, f.IngressClass, f.TLS, f.TLSIssuer = routingIngress, "traefik", tlsIssuer, "team-ca"
		}), nil, routingAnswers{Routing: routingIngress, IngressClass: "traefik", TLS: tlsIssuer, TLSIssuer: "team-ca"},
			map[string]int{"Ingress": 2}},
		"by flag, none": {flags(func(f *CLIFlags) { f.Routing = routingNone }), nil, routingAnswers{Routing: routingNone}, map[string]int{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if got := routingAnswersOf(w.config); got != tc.want {
				t.Errorf("the routing answers are\n%+v, want\n%+v", got, tc.want)
			}
			docs := writtenDocuments(t, w)
			for _, kind := range []string{"Gateway", "HTTPRoute", "Ingress"} {
				if len(docs[kind]) != tc.kinds[kind] {
					t.Errorf("the manifest has %d %s objects, want %d", len(docs[kind]), kind, tc.kinds[kind])
				}
			}
		})
	}
}

// Asked interactively, URLs on two HTTPS ports where the manifest redirects to one are entered
// again rather than end the wizard, with every check of the URL step: the URLs given are offered,
// the admin console URL on the auth server's HTTPS port, which the first offer carries too, and a
// URL on another domain is confirmed. An http auth URL names no HTTPS port (#686 section 3).
func TestWizard_AsksAgainForURLsOnTwoHTTPSPorts(t *testing.T) {
	const (
		authPrompt  = "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: "
		againPrompt = "Auth server URL (e.g., https://auth.example.com) [https://auth.example.org:8444]: "
		adminPrompt = "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org:8444]: "
	)
	for name, tc := range map[string]struct {
		first, again []scriptedStep
		want         string
	}{
		"the offer accepted": {[]scriptedStep{
			{prompt: authPrompt, answer: "https://auth.example.org:8444"},
			{prompt: adminPrompt, answer: ""},
		}, nil, "https://admin.example.org:8444"},
		"another port, entered again": {[]scriptedStep{
			{prompt: authPrompt, answer: "https://auth.example.org:8444"},
			{prompt: adminPrompt, answer: "https://admin.example.org"},
		}, []scriptedStep{
			{prompt: againPrompt, answer: ""},
			{prompt: adminPrompt, answer: ""},
		}, "https://admin.example.org:8444"},
		"entered again on another domain, confirmed": {[]scriptedStep{
			{prompt: authPrompt, answer: "https://auth.example.org:8444"},
			{prompt: adminPrompt, answer: "https://admin.example.org"},
		}, []scriptedStep{
			{prompt: againPrompt, answer: ""},
			{prompt: adminPrompt, answer: "https://admin.example.net:8444"},
			{prompt: "Continue with different domains? [y/N]: ", answer: "y"},
		}, "https://admin.example.net:8444"},
		"an http auth URL on its own port": {[]scriptedStep{
			{prompt: authPrompt, answer: "http://auth.example.org:8080"},
			{prompt: "Continue with HTTP? [y/N]: ", answer: "y"},
			{prompt: "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: ", answer: ""},
		}, nil, "https://admin.example.org"},
	} {
		t.Run(name, func(t *testing.T) {
			steps := replaceURLSteps(t, interactiveScript(deployments[deploymentKubernetes], testEngine("postgres")), tc.first...)
			at := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == routingPrompt })
			steps = slices.Insert(steps, at+1, tc.again...)
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.AdminConsoleURL != tc.want {
				t.Errorf("the admin console URL is %q, want %q", w.config.AdminConsoleURL, tc.want)
			}
			asked := strings.Contains(out.String(), "These URLs cannot be routed")
			if asked != (tc.again != nil) {
				t.Errorf("the wizard said the URLs cannot be routed: %v, want %v\n%s", asked, tc.again != nil, out)
			}
		})
	}
}

// A mode's flags the mode needs, left out, are refused naming the flag, as are two listeners on one
// port, before anything is written.
func TestWizard_RoutingFlagsAModeNeedsAreRequired(t *testing.T) {
	cases := map[string]struct {
		change func(f *CLIFlags)
		want   string
	}{
		"gateway, no class": {func(f *CLIFlags) { f.Routing = routingGateway }, "--gateway-class is required with --routing=gateway"},
		"gateway, no issuer": {func(f *CLIFlags) { f.Routing, f.GatewayClass = routingGateway, "eg" },
			"--tls-issuer is required with --tls=cluster-issuer"},
		"gateway, one port for both listeners": {func(f *CLIFlags) {
			f.Routing, f.GatewayClass, f.TLS, f.GatewayHTTPPort, f.GatewayHTTPSPort = routingGateway, "eg", tlsSecrets, 8000, 8000
		}, "--gateway-http-port and --gateway-https-port are both 8000"},
		"existing gateway, no listener": {func(f *CLIFlags) {
			f.Routing, f.GatewayName, f.GatewayNamespace = routingExistingGateway, "shared", "infra"
		}, "--auth-listener is required with --routing=existing-gateway"},
		"existing gateway, no namespace": {func(f *CLIFlags) {
			f.Routing, f.GatewayName, f.AuthListener = routingExistingGateway, "shared", "https"
		}, "--gateway-namespace is required with --routing=existing-gateway"},
		"ingress, an invalid class": {func(f *CLIFlags) { f.Routing, f.IngressClass = routingIngress, "Traefik" }, "invalid --ingress-class"},
		"the recipe, URLs on two HTTPS ports": {func(f *CLIFlags) {
			f.AuthServerURL, f.AdminConsoleURL = "https://auth.example.org:8444", "https://admin.example.org"
		}, "the auth server's URL takes HTTPS on port 8444 and the admin console's on 443"},
		"gateway, URLs on two HTTPS ports": {func(f *CLIFlags) {
			f.Routing, f.GatewayClass, f.TLS = routingGateway, "eg", tlsSecrets
			f.AuthServerURL, f.AdminConsoleURL = "https://auth.example.org:8444", "https://admin.example.org:9444"
		}, "give both URLs the same port"},
		"ingress, NetworkPolicies with no namespace": {func(f *CLIFlags) {
			f.Routing, f.TLS, f.NetworkPolicy = routingIngress, tlsExternal, true
		}, "--proxy-namespace is required with --network-policy and --routing=ingress"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := kubernetesFlags()
			tc.change(f)
			w, _, out, _ := testWizard(t, f, nil)
			err := w.setup()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("setup: %v, want an error saying %q\n%s", err, tc.want, out)
			}
			if _, statErr := os.Stat(w.paths.description); statErr == nil {
				t.Error("the manifest was written before the error")
			}
		})
	}
}

// With NetworkPolicies on, the namespace they admit is asked: envoy-gateway-system offered under the
// Envoy Gateway recipe and nothing under another mode, and --proxy-namespace answers without a
// prompt. The policies admit it and nothing else of the routing layer (#686 section 3).
func TestWizard_NetworkPoliciesAdmitTheNamespaceAnswered(t *testing.T) {
	underNone := routingScript(t, "5")
	at := slices.IndexFunc(underNone, func(s scriptedStep) bool { return s.prompt == networkPolicyPrompt })
	underNone[at].answer = "y"
	underNone = slices.Insert(underNone, at+1,
		scriptedStep{prompt: "Namespace your routing layer's proxies run in: ", answer: ""},
		scriptedStep{prompt: "Namespace your routing layer's proxies run in: ", answer: "ingress"})
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  string
	}{
		"prompted, the recipe's default":                  {&CLIFlags{}, withAnswers(t, deploymentKubernetes, map[string]string{networkPolicyPrompt: "y"}), envoyProxyNamespace},
		"prompted, none, asked again for an empty answer": {&CLIFlags{}, underNone, "ingress"},
		"by flag, the recipe's default": {func() *CLIFlags {
			f := kubernetesFlags()
			f.NetworkPolicy = true
			return f
		}(), nil, envoyProxyNamespace},
		"by flag, another": {func() *CLIFlags {
			f := kubernetesFlags()
			f.Routing, f.NetworkPolicy, f.ProxyNamespace = routingNone, true, "kube-system"
			return f
		}(), nil, "kube-system"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.ProxyNamespace != tc.want {
				t.Errorf("ProxyNamespace is %q, want %q", w.config.ProxyNamespace, tc.want)
			}
			for name, policy := range writtenDocuments(t, w)["NetworkPolicy"] {
				admitted := atPath(listAt(policy, "spec", "ingress")[0].(map[string]any)["from"].([]any)[0].(map[string]any),
					"namespaceSelector", "matchLabels").(map[string]any)["kubernetes.io/metadata.name"]
				if admitted != tc.want {
					t.Errorf("the NetworkPolicy %s admits the namespace %v, want %s", name, admitted, tc.want)
				}
			}
		})
	}
}

// Every golden that routes another way than the recipe writes what its answers say, and nothing that
// would serve Goiabada over plain HTTP where something ends TLS: a route on the Gateway's HTTP
// listener, or an Ingress without TLS. A Gateway or Ingress names the issuer only when cert-manager
// issues, and the certificates each listener or Ingress names are the Secrets answered (#686
// section 3).
func TestKubernetesManifest_RoutesAsTheAnswersSay(t *testing.T) {
	modes := map[routing]bool{}
	for _, c := range goldenCases() {
		if c.deployment != deploymentKubernetes {
			continue
		}
		config := c.config()
		modes[config.Routing] = true
		t.Run(c.name, func(t *testing.T) {
			docs := kubernetesDocuments(t, config)
			gateway, owns := docs["Gateway"]["goiabada"]
			if owns != config.ownsGateway() {
				t.Errorf("the manifest has its Gateway: %v, want %v", owns, config.ownsGateway())
			}
			certificates := map[string]string{hostOf(config.AuthServerURL): config.TLSSecretAuth, hostOf(config.AdminConsoleURL): config.TLSSecretAdmin}
			if owns {
				spec := gateway["spec"].(map[string]any)
				if spec["gatewayClassName"] != config.GatewayClass {
					t.Errorf("the Gateway's class is %v, want %s", spec["gatewayClassName"], config.GatewayClass)
				}
				checkIssuerAnnotation(t, "the Gateway", gateway, config)
				https := 0
				for _, l := range spec["listeners"].([]any) {
					listener := l.(map[string]any)
					if listener["protocol"] == "HTTP" {
						if listener["port"] != config.GatewayHTTPPort {
							t.Errorf("the HTTP listener is on %v, want %d", listener["port"], config.GatewayHTTPPort)
						}
						continue
					}
					https++
					if want := map[any]string{"auth-https": hostOf(config.AuthServerURL), "admin-https": hostOf(config.AdminConsoleURL)}[listener["name"]]; listener["hostname"] != want {
						t.Errorf("the listener %v is for %v, want %s", listener["name"], listener["hostname"], want)
					}
					ref := atPath(listener, "tls", "certificateRefs").([]any)[0].(map[string]any)["name"]
					if host := listener["hostname"].(string); ref != certificates[host] || listener["port"] != config.GatewayHTTPSPort {
						t.Errorf("the listener for %s takes its certificate from %v on port %v, want %s on %d", host, ref, listener["port"], certificates[host], config.GatewayHTTPSPort)
					}
				}
				if want := map[bool]int{true: 2, false: 0}[config.endsTLS()]; https != want {
					t.Errorf("the Gateway has %d HTTPS listeners, want %d", https, want)
				}
			}
			for name, route := range docs["HTTPRoute"] {
				parent := listAt(route, "spec", "parentRefs")[0].(map[string]any)
				if name == "goiabada-https-redirect" {
					if !config.writesRedirect() {
						t.Error("the manifest redirects on a Gateway that is not its own or ends no TLS")
					}
					continue
				}
				// The listener each route must attach to, written out rather than read from the
				// generator: the auth server's and the admin console's HTTPS listeners, the HTTP one
				// alone when TLS ends in front, or those answered on someone else's Gateway.
				wantGateway, wantNamespace := any("goiabada"), any(nil)
				wantListener := map[string]string{"goiabada-authserver": "auth-https", "goiabada-adminconsole": "admin-https"}[name]
				switch {
				case config.Routing == routingExistingGateway:
					wantGateway, wantNamespace = config.GatewayName, config.GatewayNamespace
					wantListener = map[string]string{"goiabada-authserver": config.AuthListener, "goiabada-adminconsole": config.AdminListener}[name]
				case config.TLS == tlsExternal:
					wantListener = "http"
				}
				if parent["name"] != wantGateway || parent["namespace"] != wantNamespace || parent["sectionName"] != wantListener {
					t.Errorf("%s attaches to %v, want %v/%v listener %s", name, parent, wantNamespace, wantGateway, wantListener)
				}
			}
			if config.Routing != routingIngress && len(docs["Ingress"]) != 0 {
				t.Errorf("the manifest has Ingresses under --routing=%s", config.Routing)
			}
			for name, ingress := range docs["Ingress"] {
				spec := ingress["spec"].(map[string]any)
				if class, _ := spec["ingressClassName"].(string); class != config.IngressClass {
					t.Errorf("%s has the class %q, want %q", name, class, config.IngressClass)
				}
				checkIssuerAnnotation(t, name, ingress, config)
				tls, _ := spec["tls"].([]any)
				if len(tls) != map[bool]int{true: 1, false: 0}[config.endsTLS()] {
					t.Errorf("%s has %d TLS entries, ending TLS: %v", name, len(tls), config.endsTLS())
					continue
				}
				for _, entry := range tls {
					host := entry.(map[string]any)["hosts"].([]any)[0].(string)
					if secret := entry.(map[string]any)["secretName"]; secret != certificates[host] {
						t.Errorf("%s takes the certificate of %s from %v, want %s", name, host, secret, certificates[host])
					}
				}
			}
		})
	}
	for _, mode := range routings {
		if !modes[mode] {
			t.Errorf("no golden routes with --routing=%s", mode)
		}
	}
}

// TLS Secrets the operator supplies are created where their namespace already exists: in the first
// step when it existed before, and after the deploy that creates it otherwise, which a namespaced
// Secret created first would be refused for (#686 section 3).
func TestCompletionMessage_CreatesTheTLSSecretsOnceTheirNamespaceExists(t *testing.T) {
	for _, mode := range []routing{routingGateway, routingIngress} {
		for _, exists := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, namespace exists: %v", mode, exists), func(t *testing.T) {
				config := goldenConfig(deploymentKubernetes, "postgres")
				config.Routing, config.GatewayClass, config.TLS, config.NamespaceExists = mode, "eg", tlsSecrets, exists
				var buf bytes.Buffer
				printKubernetesInstructions(&console{w: &buf}, config, resolveOutputPaths(config.Deployment, ""))
				said := buf.String()
				create, apply := strings.Index(said, "kubectl create secret tls"), strings.Index(said, "kubectl apply -f")
				if create < 0 || apply < 0 || strings.Count(said, "kubectl create secret tls") != 1 {
					t.Fatalf("the message has no single Secret creation and apply:\n%s", said)
				}
				if (create < apply) != exists {
					t.Errorf("the Secrets are created before the apply: %v, want %v\n%s", create < apply, exists, said)
				}
			})
		}
	}
}

// checkIssuerAnnotation holds what's annotations to naming the issuer answered, under the key for
// its kind, cert-manager.io/cluster-issuer or cert-manager.io/issuer (cert-manager docs,
// usage/gateway.md), exactly when cert-manager issues the certificates: from an issuer, and not
// with TLS ended in front, which only the gateway and ingress modes ask.
func checkIssuerAnnotation(t *testing.T, what string, doc map[string]any, config *Config) {
	t.Helper()
	annotations, _ := doc["metadata"].(map[string]any)["annotations"].(map[string]any)
	wantKey := map[tlsSource]string{tlsClusterIssuer: "cert-manager.io/cluster-issuer", tlsIssuer: "cert-manager.io/issuer"}[config.TLS]
	for _, key := range []string{"cert-manager.io/cluster-issuer", "cert-manager.io/issuer"} {
		want := ""
		if key == wantKey {
			want = config.TLSIssuer
		}
		if got, _ := annotations[key].(string); got != want {
			t.Errorf("%s has %s %q, want %q", what, key, got, want)
		}
	}
}

// The completion message gives the steps of the mode answered: the Envoy Gateway install for the
// recipe alone, the check of plain HTTP's redirect wherever the manifest writes none, and, with TLS
// ended in front, that the routing layer must not redirect itself, which loops (#686 section 3).
func TestCompletionMessage_FollowsTheRouting(t *testing.T) {
	for _, c := range goldenCases() {
		if c.deployment != deploymentKubernetes || c.hostile {
			continue
		}
		config := c.config()
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			printKubernetesInstructions(&console{w: &buf}, config, resolveOutputPaths(config.Deployment, ""))
			said := strings.Join(strings.Fields(buf.String()), " ")
			for line, want := range map[string]bool{
				"Install Envoy Gateway":                                 config.servedByEnvoyGateway(),
				gatewayDocsURL + ".":                                    config.servedByEnvoyGateway() || (config.Routing == routingGateway && config.issuesWithCertManager()),
				routingDocsURL:                                          !config.servedByEnvoyGateway(),
				"curl -sI http://":                                      !config.writesRedirect(),
				"The routing layer must not redirect":                   config.asksTLS() && config.TLS == tlsExternal,
				"kubectl get certificates":                              config.issuesWithCertManager(),
				fmt.Sprintf("namespace %s on its", config.K8sNamespace): config.Routing == routingExistingGateway,
			} {
				if got := strings.Contains(said, line); got != want {
					t.Errorf("the message says %q: %v, want %v\n%s", line, got, want, buf.String())
				}
			}
		})
	}
}
