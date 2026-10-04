package main

import (
	"path/filepath"
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
	// servedByEnvoyGateway says the manifest is served through Envoy Gateway, so the type asks its
	// traffic policy and whether a NetworkPolicy admits only Envoy (#396 decisions 4 and 5).
	servedByEnvoyGateway bool
	// asksRateLimiter says the type asks whether to turn the auth server's rate limiter on, and
	// writes the answer explicitly (#396 decision 9). Local testing never asks.
	asksRateLimiter bool
	// routesByHost says the manifest routes and certifies each URL by its host, which must then be
	// a lowercase domain name (validateListenerHostname) and not the other URL's host.
	routesByHost bool

	// outputFile is the default name of the file describing the deployment, and secretsFile the
	// default name of the file beside it holding every secret, empty for a type whose one file is
	// both. When --output names a file, the secrets file's name is that name with secretsSuffix
	// before its extension (#396 decision 14).
	outputFile    string
	secretsFile   string
	secretsSuffix string
	// generate writes the description, to be written at paths, and generateSecrets the secrets
	// file, for a type that has one; each header names the files by the names paths give them.
	generate          func(config *Config, paths outputPaths) string
	generateSecrets   func(config *Config, paths outputPaths) string
	printInstructions func(out *console, config *Config, paths outputPaths)
}

// deployments is the deployment menu, in its order, indexed by deploymentType.
var deployments = []*deployment{
	{ //nolint:gosec // G101: secretsFile and secretsSuffix name a file, and hold no credential
		kind:              deploymentLocal,
		number:            "1",
		name:              "local",
		menuLabel:         "Local testing (HTTP only) - for development/testing",
		displayName:       "Local testing (Docker)",
		outputFile:        "docker-compose.yml",
		secretsFile:       "docker-compose.override.yml",
		secretsSuffix:     ".override",
		generate:          generateDockerCompose,
		generateSecrets:   generateComposeOverride,
		printInstructions: printComposeInstructions,
	},
	{ //nolint:gosec // G101: secretsFile and secretsSuffix name a file, and hold no credential
		kind:              deploymentProduction,
		number:            "2",
		name:              "production",
		menuLabel:         "Production with reverse proxy (Cloudflare/Nginx)",
		displayName:       "Production with reverse proxy",
		asksURLs:          true,
		behindProxy:       true,
		asksRateLimiter:   true,
		outputFile:        "docker-compose.yml",
		secretsFile:       "docker-compose.override.yml",
		secretsSuffix:     ".override",
		generate:          generateDockerCompose,
		generateSecrets:   generateComposeOverride,
		printInstructions: printComposeInstructions,
	},
	{
		kind:                 deploymentKubernetes,
		number:               "3",
		name:                 "kubernetes",
		aliases:              []string{"k8s"},
		menuLabel:            "Kubernetes cluster",
		displayName:          "Kubernetes",
		asksURLs:             true,
		asksNamespace:        true,
		externalDatabase:     true,
		routesByHost:         true,
		servedByEnvoyGateway: true,
		asksRateLimiter:      true,
		outputFile:           "goiabada-k8s.yaml",
		secretsFile:          "goiabada-secrets.yaml",
		secretsSuffix:        "-secrets",
		generate:             generateKubernetesManifests,
		generateSecrets:      generateKubernetesSecrets,
		printInstructions:    printKubernetesInstructions,
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
		asksRateLimiter:   true,
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

// secretsFileBeside is the name of the file holding the secrets beside a description --output names
// name: name itself for a type whose one file is both, and otherwise name with the type's suffix
// before its extension, -secrets for Kubernetes and .override for Compose, which names an override
// that way, so a compose.yaml's is the compose.override.yaml Compose merges by itself.
func (d *deployment) secretsFileBeside(name string) string {
	if d.secretsFile == "" {
		return name
	}
	extension := filepath.Ext(name)
	return strings.TrimSuffix(name, extension) + d.secretsSuffix + extension
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
