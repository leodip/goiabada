package main

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// The prompts of the Container images step: the repository, Docker Hub's by default, the digest pin
// a release build asks of a mirror, and the pull secret Kubernetes asks, none by default (#686
// section 5).
const (
	imageRepositoryPrompt = "Image repository [docker.io/leodip/goiabada]: "
	imageDigestPrompt     = "Pin the images by digest? [Y/n]: "
	imagePullSecretPrompt = "Image pull secret (blank for none): "
)

// A repository is what a runtime pulls one by, with the registry or without, and with no tag or
// digest, which the wizard writes itself.
func TestValidateImageRepository_TakesWhatARuntimePulls(t *testing.T) {
	for _, repository := range []string{
		"docker.io/leodip/goiabada",
		"leodip/goiabada",
		"ghcr.io/leodip/goiabada",
		"registry.example.com/mirror/goiabada",
		"registry.example.com:5000/goiabada",
		"localhost:5000/goiabada",
		"harbor.example.com/dockerhub-proxy/leodip/goiabada",
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com/goiabada",
		"Registry.Example.com/team_a/goiabada-images",
	} {
		if err := validateImageRepository(repository); err != nil {
			t.Errorf("%s is refused: %v", repository, err)
		}
	}
	for _, repository := range []string{
		"",
		"registry.example.com/mirror/goiabada:authserver-1.8.0",
		"registry.example.com/mirror/goiabada@sha256:" + strings.Repeat("a", 64),
		"https://registry.example.com/goiabada",
		"registry.example.com/Mirror/goiabada",
		"registry.example.com/mirror//goiabada",
		"registry.example.com/mirror/goiabada/",
		"registry.example.com/mirror goiabada",
		"registry.example.com/" + strings.Repeat("a", 255),
	} {
		if err := validateImageRepository(repository); err == nil {
			t.Errorf("%q is taken", repository)
		}
	}
}

// containerImages is the image each server's container runs in the manifest, by Deployment.
func containerImages(t *testing.T, config *Config) map[string]string {
	t.Helper()
	docs := kubernetesDocuments(t, config)
	images := map[string]string{}
	for _, w := range workloads {
		podSpec := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec")
		container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), w.deployment+"'s containers")
		images[w.deployment] = at[string](t, container, "image")
	}
	return images
}

// A release build pins each image line to its own image's digest, which a runtime pulls by alone, so
// one image's digest beside the other's tag would run the wrong server; a source build carries no
// digest, and an operator whose mirror holds other digests asks for none.
func TestImages_AReleaseBuildPinsEachImageToItsOwnDigest(t *testing.T) {
	withRelease(t)
	config := kubernetesConfig()
	config.ImageRepository = "registry.example.com/mirror/goiabada"
	want := map[string]string{
		"goiabada-authserver":   "registry.example.com/mirror/goiabada:authserver-1.8.0@" + releaseAuthServerDigest,
		"goiabada-adminconsole": "registry.example.com/mirror/goiabada:adminconsole-1.8.0@" + releaseAdminConsoleDigest,
	}
	if got := containerImages(t, config); got["goiabada-authserver"] != want["goiabada-authserver"] || got["goiabada-adminconsole"] != want["goiabada-adminconsole"] {
		t.Errorf("the manifest runs %v, want %v", got, want)
	}
	compose := goldenConfig(deploymentProduction, "postgres")
	compose.ImageRepository = config.ImageRepository
	doc := only[map[string]any](t, toAny(yamlDocuments(t, descriptionOf(compose))), "the Compose file's documents")
	for service, image := range want {
		if got := at[string](t, doc, "services", service, "image"); got != image {
			t.Errorf("the Compose service %s runs %q, want %q", service, got, image)
		}
	}

	config.ImageDigest = false
	if got := containerImages(t, config)["goiabada-authserver"]; got != "registry.example.com/mirror/goiabada:authserver-1.8.0" {
		t.Errorf("unpinned, the auth server runs %q", got)
	}
}

func TestImages_ASourceBuildWritesTheTagAlone(t *testing.T) {
	config := kubernetesConfig()
	if got := containerImages(t, config)["goiabada-authserver"]; got != "docker.io/leodip/goiabada:authserver-latest" {
		t.Errorf("a source build's auth server runs %q", got)
	}
}

// Both pod specs name the pull secret, when there is one, and neither names one otherwise.
func TestKubernetesManifest_BothPodsNameThePullSecret(t *testing.T) {
	for _, secret := range []string{"", "registry-credentials"} {
		config := kubernetesConfig()
		config.ImagePullSecret = secret
		docs := kubernetesDocuments(t, config)
		for _, w := range workloads {
			podSpec := at[map[string]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec")
			secrets, named := podSpec["imagePullSecrets"]
			switch {
			case secret == "" && named:
				t.Errorf("%s names pull secrets %v, with none answered", w.deployment, secrets)
			case secret != "":
				entry := only[map[string]any](t, at[[]any](t, podSpec, "imagePullSecrets"), w.deployment+"'s pull secrets")
				if entry["name"] != secret {
					t.Errorf("%s pulls with %v, want %s", w.deployment, entry, secret)
				}
			}
		}
	}
}

// A release build asks whether to pin a mirror's images, which may hold other digests, and never
// asks of the repositories the release pushed to, whose digests are its own; a source build has no
// digest to pin, and never asks.
func TestWizard_AsksThePinOfAMirrorAlone(t *testing.T) {
	d, e := deployments[deploymentKubernetes], testEngine("postgres")
	mirror := "registry.example.com/mirror/goiabada"
	for _, tc := range []struct {
		name       string
		release    bool
		repository string
		pin        string
		pinned     bool
	}{
		{name: "a release build, Docker Hub", release: true, repository: "", pinned: true},
		{name: "a release build, GitHub", release: true, repository: githubImageRepository, pinned: true},
		{name: "a release build, a mirror, pinned", release: true, repository: mirror, pin: "", pinned: true},
		{name: "a release build, a mirror, unpinned", release: true, repository: mirror, pin: "n", pinned: false},
		{name: "a source build, a mirror", release: false, repository: mirror},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.release {
				withRelease(t)
			}
			var steps []scriptedStep
			for _, step := range interactiveScript(d, e) {
				switch step.prompt {
				case imageRepositoryPrompt:
					step.answer = tc.repository
					steps = append(steps, step)
					if tc.release && tc.repository == mirror {
						steps = append(steps, scriptedStep{prompt: imageDigestPrompt, answer: tc.pin})
					}
				case imagePullSecretPrompt:
					step.answer = "registry-credentials"
					steps = append(steps, step)
				default:
					steps = append(steps, step)
				}
			}
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if got := w.config.pinsDigests(); got != tc.pinned {
				t.Errorf("pinned is %v, want %v", got, tc.pinned)
			}
			if w.config.ImagePullSecret != "registry-credentials" {
				t.Errorf("the pull secret is %q", w.config.ImagePullSecret)
			}
		})
	}
}

// The flags are refused naming themselves when no runtime could pull what they name, and the pull
// secret is read by Kubernetes alone, since Compose pulls with the host's docker login.
func TestWizard_TheImageFlags(t *testing.T) {
	k8s := func(f CLIFlags) *CLIFlags {
		f.DeploymentType, f.DBType, f.AuthServerURL, f.DBHost, f.DBPassword, f.SkipDBTest = "kubernetes", "postgres", "https://auth.example.org", "pg.internal", "db-secret", true
		return &f
	}
	for name, tc := range map[string]struct {
		flags *CLIFlags
		err   string
	}{
		"a tag in the repository":   {k8s(CLIFlags{ImageRepository: "registry.example.com/goiabada:1.8.0"}), "invalid --image-repository"},
		"a pull secret no name":     {k8s(CLIFlags{ImagePullSecret: "Registry_Credentials"}), "invalid --image-pull-secret"},
		"a mirror and a secret":     {k8s(CLIFlags{ImageRepository: "registry.example.com/goiabada", ImagePullSecret: "regcred"}), ""},
		"a pull secret for Compose": {&CLIFlags{DeploymentType: "local", DBType: "sqlite", ImagePullSecret: "regcred"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			w, _, out, _ := testWizard(t, tc.flags, nil)
			err := w.setup()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("setup returned %v, want %s\n%s", err, tc.err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			wantSecret := tc.flags.ImagePullSecret
			if w.config.Deployment.kind != deploymentKubernetes {
				wantSecret = ""
			}
			if w.config.ImagePullSecret != wantSecret {
				t.Errorf("the pull secret is %q, want %q", w.config.ImagePullSecret, wantSecret)
			}
		})
	}
}

// With a pull secret, the deploy step says to create it once the namespace exists, keyed by the
// registry the repository names, Docker Hub's for a repository naming none.
func TestKubernetesInstructions_CreateThePullSecret(t *testing.T) {
	for _, tc := range []struct{ repository, registry string }{
		{"registry.example.com:5000/mirror/goiabada", "registry.example.com:5000"},
		{"team/goiabada", "docker.io"},
	} {
		config := kubernetesConfig()
		config.ImageRepository, config.ImagePullSecret = tc.repository, "registry-credentials"
		var buf strings.Builder
		printDeployStep(&console{w: &buf}, config, config.Deployment.defaultPaths(), 2)
		want := "kubectl create secret docker-registry registry-credentials -n identity --docker-server=" + tc.registry + " "
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the deploy step does not say %q:\n%s", want, buf.String())
		}
	}
}

// build-binaries.sh refuses a digest that is none, and one image's digest without the other's, which
// would pin one image line alone, before it builds anything.
func TestBuildBinaries_RefusesDigestsItCouldNotPin(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	for name, args := range map[string][]string{
		"a digest that is none":           {"--authserver-digest", "sha256:abc", "--adminconsole-digest", digest},
		"the admin console's digest left": {"--authserver-digest", digest},
		"an uppercase digest":             {"--authserver-digest", digest, "--adminconsole-digest", strings.ToUpper(digest)},
	} {
		t.Run(name, func(t *testing.T) {
			output, err := exec.Command("bash", append([]string{"build-binaries.sh"}, args...)...).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("build-binaries.sh exited with %v, want 2\n%s", err, output)
			}
			if !strings.Contains(string(output), "take both images' digests") {
				t.Errorf("the refusal does not say why:\n%s", output)
			}
		})
	}
}

// A run under --keep-secrets that names a pull secret writes no secrets file, and no file of the
// wizard's holds the pull secret: its completion message has the operator check it exists before
// applying the manifest, as a first install's does.
func TestRegeneratedMessage_ChecksThePullSecretBeforeTheApply(t *testing.T) {
	config := kubernetesConfig()
	config.KeepSecrets = true
	config.ImageRepository = "registry.example.com/mirror/goiabada"
	var without strings.Builder
	printRegeneratedMessage(&console{w: &without}, config, config.Deployment.defaultPaths())
	if strings.Contains(without.String(), "pull secret") {
		t.Errorf("with no pull secret, the message names one:\n%s", without.String())
	}

	config.ImagePullSecret = "registry-credentials"
	var buf strings.Builder
	printRegeneratedMessage(&console{w: &buf}, config, config.Deployment.defaultPaths())
	out := buf.String()
	check := strings.Index(out, "kubectl get secret registry-credentials -n identity")
	create := strings.Index(out, "kubectl create secret docker-registry registry-credentials -n identity --docker-server=registry.example.com ")
	apply := strings.Index(out, "kubectl apply -f goiabada-k8s.yaml")
	if check < 0 || create < 0 || apply < 0 || check > apply || create > apply {
		t.Errorf("the message does not check and create the pull secret before the apply:\n%s", out)
	}
	if !strings.Contains(out, "  4. Wait for both servers to roll out:") {
		t.Errorf("the steps after the pull secret are not renumbered:\n%s", out)
	}
}
