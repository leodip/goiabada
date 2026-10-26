package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// The repositories a release pushes both images to, in one push, so the two hold the same digests:
// Docker Hub's, which the files name by default, in full, since CRI-O, the runtime OpenShift uses,
// resolves a short name only through registries its configuration lists, and GitHub's (#686
// section 5).
const (
	defaultImageRepository = "docker.io/leodip/goiabada"
	githubImageRepository  = "ghcr.io/leodip/goiabada"
)

// imageComponents are the two servers' images, each named by the component its tag begins with.
const (
	authServerImage   = "authserver"
	adminConsoleImage = "adminconsole"
)

// imageRepositoryPattern is a repository as the distribution reference grammar spells one, with no
// tag or digest: an optional registry host, with a port, then path components of lowercase
// alphanumerics joined by '.', '_', '__' or dashes, separated by '/'.
var imageRepositoryPattern = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// validateImageRepository refuses what no runtime pulls as a repository, a tag or a digest after it
// among them, which the wizard writes itself.
func validateImageRepository(repository string) error {
	if repository == "" {
		return errs.New("the repository cannot be empty")
	}
	if len(repository) > 255 {
		return errs.Errorf("%s is too long (max 255 characters)", repository)
	}
	if !imageRepositoryPattern.MatchString(repository) {
		return errs.Errorf("%s is not a repository, such as registry.example.com/mirror/goiabada: lowercase after the registry, with no tag or digest", repository)
	}
	return nil
}

// releaseDigests says the build carries the digests of the images its release pushed, which a
// release build is stamped with and a source build is not.
func releaseDigests() bool {
	return authserverDigest != "" && adminconsoleDigest != ""
}

// publishedRepository says the repository is one the release pushed to, whose digests are the
// release's whatever copies a mirror holds.
func publishedRepository(repository string) bool {
	switch repository {
	case defaultImageRepository, "leodip/goiabada", githubImageRepository:
		return true
	}
	return false
}

// pinsDigests says each image line names the digest its release pushed beside the tag: asked for,
// and carried by the build.
func (c *Config) pinsDigests() bool {
	return c.ImageDigest && releaseDigests()
}

// image is the reference the component's image is pulled by: the repository, the tag of the
// wizard's release, and, pinned, the digest that release pushed, which a runtime pulls by alone.
func (c *Config) image(component string) string {
	reference := c.ImageRepository + ":" + component + "-" + imageTag
	if !c.pinsDigests() {
		return reference
	}
	if component == authServerImage {
		return reference + "@" + authserverDigest
	}
	return reference + "@" + adminconsoleDigest
}

// imageRegistry is the registry host the repository is pulled from, which an image pull secret's
// credentials are keyed by: its first component when that names a host, as the reference grammar
// tells one, and Docker Hub otherwise.
func (c *Config) imageRegistry() string {
	first, _, found := strings.Cut(c.ImageRepository, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first
	}
	return "docker.io"
}

// imageAnswer is the images answer the summary reports.
func (c *Config) imageAnswer() string {
	switch {
	case c.pinsDigests():
		return fmt.Sprintf("%s, %s pinned by digest", c.ImageRepository, imageTag)
	case releaseDigests():
		return fmt.Sprintf("%s, %s by tag alone", c.ImageRepository, imageTag)
	}
	return fmt.Sprintf("%s, %s", c.ImageRepository, imageTag)
}

// askImages asks where both servers' images are pulled from, Docker Hub by default, whether a
// mirror's copies are pulled by the release's digests, and, on Kubernetes, the Secret holding the
// registry's credentials (#686 section 5).
func (w *wizard) askImages() error {
	if !w.interactive {
		return w.imagesFromFlags()
	}
	c := w.config
	kubernetes := c.Deployment.kind == deploymentKubernetes
	w.out.printf("Both servers' images are pulled from Docker Hub, as %s. Where only a\n", defaultImageRepository)
	w.out.println("registry of your own can be reached, or pulled from, name the repository of the mirror")
	w.out.println("holding them there, such as registry.example.com/mirror/goiabada, with this release's")
	w.out.printf("tags, %s-%s and %s-%s.\n", authServerImage, imageTag, adminConsoleImage, imageTag)
	w.out.println()
	var err error
	if c.ImageRepository, err = w.validated("Image repository", defaultImageRepository, "repository", validateImageRepository); err != nil {
		return err
	}
	c.ImageDigest = true
	if releaseDigests() && !publishedRepository(c.ImageRepository) {
		w.out.println()
		w.out.println("Each image line names the digest this release pushed beside its tag, and is pulled by")
		w.out.println("that digest alone, so no registry can change what runs. A mirror holds the release's")
		w.out.println("digests when it copies every platform: a pull-through cache, skopeo copy --all or")
		w.out.println("crane copy. One filled by docker push holds a single platform under another digest,")
		w.out.println("which a pinned image line cannot be pulled from.")
		w.out.println()
		if c.ImageDigest, err = w.yesNo("Pin the images by digest?", true); err != nil {
			return err
		}
	}
	if !kubernetes {
		return nil
	}
	w.out.println()
	w.out.println("A registry that asks for credentials needs an image pull secret, a Secret of type")
	w.out.printf("kubernetes.io/dockerconfigjson in %s, which you create. Leave it blank when the nodes\n", c.K8sNamespace)
	w.out.println("pull without one: the registry admits them, or they hold its credentials already, as")
	w.out.println("managed clusters' nodes do for their cloud's registry.")
	w.out.println()
	c.ImagePullSecret, err = w.validated("Image pull secret (blank for none)", "", "name", func(name string) error {
		if name == "" {
			return nil
		}
		return validateObjectName(name)
	})
	return err
}

// imagesFromFlags is askImages answered by --image-repository, --image-digest and
// --image-pull-secret.
func (w *wizard) imagesFromFlags() error {
	c, f := w.config, w.flags
	c.ImageRepository = f.ImageRepository
	if c.ImageRepository == "" {
		c.ImageRepository = defaultImageRepository
	}
	if err := validateImageRepository(c.ImageRepository); err != nil {
		return errs.Wrap(err, "invalid --image-repository")
	}
	c.ImageDigest = f.ImageDigest.or(true)
	w.out.info("Images: %s", c.imageAnswer())
	if c.Deployment.kind != deploymentKubernetes || f.ImagePullSecret == "" {
		return nil
	}
	if err := validateObjectName(f.ImagePullSecret); err != nil {
		return errs.Wrap(err, "invalid --image-pull-secret")
	}
	c.ImagePullSecret = f.ImagePullSecret
	w.out.info("Image pull secret: %s", c.ImagePullSecret)
	return nil
}
