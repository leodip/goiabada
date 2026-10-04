package main

import (
	"slices"
	"strings"
)

// deploymentType names one of the four deployments the wizard configures. It indexes deployments,
// whose row carries every fact that differs between them (#430).
type deploymentType int

const (
	deploymentLocal deploymentType = iota
	deploymentProduction
	deploymentKubernetes
	deploymentNative
)

// deployment is one deployment type's row.
type deployment struct {
	kind deploymentType
	// number is the type's place in the menu and its numeric --type value, one field so the two
	// cannot disagree.
	number string
	// name is the --type flag's canonical value.
	name    string
	aliases []string
	// menuLabel is what the menu offers and displayName what the summary reports.
	menuLabel   string
	displayName string

	// asksURLs is false for local testing, which is served on localhost whatever the operator
	// would type.
	asksURLs      bool
	asksNamespace bool
	// externalDatabase says the database is the operator's, reached by host and credentials,
	// rather than a service of the generated compose file.
	externalDatabase bool
	// behindProxy says the Compose services sit behind a reverse proxy on the same host: they
	// trust its forwarded headers and listen on loopback alone.
	behindProxy bool
	// asksLocalProxy says the type asks whether a reverse proxy on the same machine forwards to it,
	// which decides the env file's listen hosts and proxy trust (#396 decision 7).
	asksLocalProxy bool
	// routesByHost says the manifest routes and certifies each URL by its host, which must then be
	// a lowercase domain name (validateListenerHostname) and not the other URL's host.
	routesByHost bool

	outputFile        string
	generate          func(config *Config) string
	printInstructions func(out *console, config *Config, outputPath string)
}

// deployments is the deployment menu, in its order, indexed by deploymentType.
var deployments = []*deployment{
	{
		kind:              deploymentLocal,
		number:            "1",
		name:              "local",
		menuLabel:         "Local testing (HTTP only) - for development/testing",
		displayName:       "Local testing (Docker)",
		outputFile:        "docker-compose.yml",
		generate:          generateDockerCompose,
		printInstructions: printComposeInstructions,
	},
	{
		kind:              deploymentProduction,
		number:            "2",
		name:              "production",
		menuLabel:         "Production with reverse proxy (Cloudflare/Nginx)",
		displayName:       "Production with reverse proxy",
		asksURLs:          true,
		behindProxy:       true,
		outputFile:        "docker-compose.yml",
		generate:          generateDockerCompose,
		printInstructions: printComposeInstructions,
	},
	{
		kind:              deploymentKubernetes,
		number:            "3",
		name:              "kubernetes",
		aliases:           []string{"k8s"},
		menuLabel:         "Kubernetes cluster",
		displayName:       "Kubernetes",
		asksURLs:          true,
		asksNamespace:     true,
		externalDatabase:  true,
		routesByHost:      true,
		outputFile:        "goiabada-k8s.yaml",
		generate:          generateKubernetesManifests,
		printInstructions: printKubernetesInstructions,
	},
	{
		kind:              deploymentNative,
		number:            "4",
		name:              "native",
		aliases:           []string{"binaries"},
		menuLabel:         "Native binaries",
		displayName:       "Native binaries",
		asksURLs:          true,
		externalDatabase:  true,
		asksLocalProxy:    true,
		outputFile:        "goiabada.env",
		generate:          generateEnvFile,
		printInstructions: printNativeInstructions,
	},
}

// resolveDeployment reads a --type value or a menu answer: a type's name, one of its aliases or
// its number, in any case.
func resolveDeployment(value string) (*deployment, bool) {
	value = strings.ToLower(value)
	for _, d := range deployments {
		if value == d.number || value == d.name || slices.Contains(d.aliases, value) {
			return d, true
		}
	}
	return nil, false
}

func deploymentNames() []string {
	names := make([]string, 0, len(deployments))
	for _, d := range deployments {
		names = append(names, d.name)
	}
	return names
}

// accepts says whether the deployment can run on the engine: Kubernetes only on one its manifests
// may use.
func (d *deployment) accepts(e *engine) bool {
	return d.kind != deploymentKubernetes || e.kubernetes
}

// acceptedEngines lists the engines the deployment accepts, in menu order.
func (d *deployment) acceptedEngines() []*engine {
	var accepted []*engine
	for _, e := range engines {
		if d.accepts(e) {
			accepted = append(accepted, e)
		}
	}
	return accepted
}
