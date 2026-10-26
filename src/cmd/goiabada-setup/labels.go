package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// keyValue is one label or annotation.
type keyValue struct{ key, value string }

// labelSet is --labels: key=value pairs separated by commas, in the order given.
type labelSet []keyValue

// String is the labels as the summary reports them, key=value separated by commas. A nil receiver
// is no label, because the flag package may call String on one.
func (l *labelSet) String() string {
	if l == nil {
		return ""
	}
	return joinPairs(*l)
}

// Set reads the labels with parseLabels, whose refusal the flag package reports naming the flag.
func (l *labelSet) Set(value string) error {
	labels, err := parseLabels(value)
	*l = labels
	return err
}

// podMonitorLabelSet is --podmonitor-labels, read as labelSet is but with parsePodMonitorLabels.
type podMonitorLabelSet []keyValue

// String is the labels as the summary reports them, key=value separated by commas.
func (l *podMonitorLabelSet) String() string {
	if l == nil {
		return ""
	}
	return joinPairs(*l)
}

// Set reads the labels with parsePodMonitorLabels, whose refusal the flag package reports naming the
// flag.
func (l *podMonitorLabelSet) Set(value string) error {
	labels, err := parsePodMonitorLabels(value)
	*l = labels
	return err
}

// annotationSet is --annotations: key=value pairs separated by commas, in the order given.
type annotationSet []keyValue

// String is the annotations as the summary reports them, key=value separated by commas.
func (a *annotationSet) String() string {
	if a == nil {
		return ""
	}
	return joinPairs(*a)
}

// Set reads the annotations with parseAnnotations, whose refusal the flag package reports naming the
// flag.
func (a *annotationSet) Set(value string) error {
	annotations, err := parseAnnotations(value)
	*a = annotations
	return err
}

// joinPairs writes pairs as key=value separated by commas, as they are read.
func joinPairs(pairs []keyValue) string {
	written := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		written = append(written, pair.key+"="+pair.value)
	}
	return strings.Join(written, ", ")
}

// The label syntax Kubernetes accepts ("Labels and Selectors", syntax and character set): a name,
// and a value unless it is empty, of at most 63 characters, alphanumeric at both ends with dashes,
// underscores and dots between; a key's optional prefix is a DNS subdomain of at most 253. An
// annotation's key has the same syntax, and its value is any text.
var (
	labelNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	dnsSubdomain     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// parseLabels reads a label set written key=value, pairs separated by commas and spaces around
// either ignored, refusing a key or value Kubernetes would refuse, a key given twice and one the
// manifest sets itself. Blank is no label.
func parseLabels(value string) ([]keyValue, error) {
	return parseLabelsReserving(value, reservedLabel)
}

// parsePodMonitorLabels reads the PodMonitor's own labels as parseLabels reads every object's, but
// takes app, which the PodMonitor itself doesn't carry, as the wizards before the standard labels
// did.
func parsePodMonitorLabels(value string) ([]keyValue, error) {
	return parseLabelsReserving(value, func(key string) bool { return strings.HasPrefix(key, standardLabelPrefix) })
}

// parseLabelsReserving reads a label set, refusing a key reserved says the manifest sets itself.
func parseLabelsReserving(value string, reserved func(key string) bool) ([]keyValue, error) {
	labels, err := parsePairs(value, "label", reserved)
	if err != nil {
		return nil, err
	}
	for _, label := range labels {
		if label.value != "" && (len(label.value) > 63 || !labelNamePattern.MatchString(label.value)) {
			return nil, errs.Errorf("%q is not a label value: at most 63 letters, digits, '-', '_' and '.', starting and ending with a letter or digit", label.value)
		}
	}
	return labels, nil
}

// parseAnnotations reads annotations written as parseLabels reads labels, whose values are any text
// a generated file can carry but a comma, which separates the pairs.
func parseAnnotations(value string) ([]keyValue, error) {
	annotations, err := parsePairs(value, "annotation", reservedAnnotation)
	if err != nil {
		return nil, err
	}
	for _, annotation := range annotations {
		if err := checkWritable(annotation.value); err != nil {
			return nil, errs.Wrapf(err, "the annotation %s cannot be written to the configuration", annotation.key)
		}
	}
	return annotations, nil
}

// parsePairs reads key=value pairs separated by commas, refusing a pair with no '=', a key that is no
// label key, one given twice, and one reserved says the manifest sets itself.
func parsePairs(value, what string, reserved func(key string) bool) ([]keyValue, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var pairs []keyValue
	seen := map[string]bool{}
	for _, pair := range strings.Split(value, ",") {
		key, pairValue, found := strings.Cut(pair, "=")
		key, pairValue = strings.TrimSpace(key), strings.TrimSpace(pairValue)
		if !found {
			return nil, errs.Errorf("%q is not key=value", strings.TrimSpace(pair))
		}
		if err := validateMetadataKey(key, what); err != nil {
			return nil, err
		}
		if reserved(key) {
			return nil, errs.Errorf("the manifest sets the %s %s itself", what, key)
		}
		if seen[key] {
			return nil, errs.Errorf("the %s %s is given twice", what, key)
		}
		seen[key] = true
		pairs = append(pairs, keyValue{key, pairValue})
	}
	return pairs, nil
}

// validateMetadataKey refuses a label or annotation key Kubernetes would refuse.
func validateMetadataKey(key, what string) error {
	name := key
	if prefix, rest, found := strings.Cut(key, "/"); found {
		if len(prefix) > 253 || !dnsSubdomain.MatchString(prefix) {
			return errs.Errorf("%q is not %s key: its prefix, %q, is not a lowercase DNS subdomain", key, article(what), prefix)
		}
		name = rest
	}
	if len(name) > 63 || !labelNamePattern.MatchString(name) {
		return errs.Errorf("%q is not %s key: its name is at most 63 letters, digits, '-', '_' and '.', starting and ending with a letter or digit", key, article(what))
	}
	return nil
}

// article is what with its indefinite article.
func article(what string) string {
	if strings.HasPrefix(what, "a") {
		return "an " + what
	}
	return "a " + what
}

// standardLabelPrefix is the prefix of the standard labels, every one of which the manifest sets.
const standardLabelPrefix = "app.kubernetes.io/"

// reservedLabel says the manifest sets the label key itself: app, which the selectors match, the
// standard labels, and the Namespace's Pod Security labels.
func reservedLabel(key string) bool {
	return key == "app" || strings.HasPrefix(key, standardLabelPrefix) || slices.Contains(podSecurityLabels, key)
}

// reservedAnnotation says the manifest sets the annotation key itself: the config checksum, the
// prometheus.io scrape annotations and cert-manager's issuer annotations.
func reservedAnnotation(key string) bool {
	return strings.HasPrefix(key, "goiabada.dev/") || slices.Contains([]string{
		"prometheus.io/scrape", "prometheus.io/port", "prometheus.io/path",
		"cert-manager.io/cluster-issuer", "cert-manager.io/issuer",
	}, key)
}

// The servers' components, as the standard component label names them.
const (
	authServerComponent   = "authserver"
	adminConsoleComponent = "adminconsole"
)

// componentOf is the component an object named after a server's Deployment belongs to.
func componentOf(name string) string {
	return strings.TrimPrefix(name, "goiabada-")
}

// standardLabels are the app.kubernetes.io labels every object carries, by the Kubernetes docs'
// "Recommended Labels": name and part-of goiabada, instance the namespace, which holds one
// installation, component the server the object belongs to, left off an object both share, version
// the image tag, and managed-by the wizard (#686 section 6). Selectors keep matching app alone: a
// Deployment's selector cannot change once it exists.
func (c *Config) standardLabels(component string) []keyValue {
	labels := []keyValue{
		{standardLabelPrefix + "name", "goiabada"},
		{standardLabelPrefix + "instance", c.K8sNamespace},
	}
	if component != "" {
		labels = append(labels, keyValue{standardLabelPrefix + "component", component})
	}
	return append(labels,
		keyValue{standardLabelPrefix + "part-of", "goiabada"},
		keyValue{standardLabelPrefix + "version", imageTag},
		keyValue{standardLabelPrefix + "managed-by", "goiabada-setup"},
	)
}

// objectMetadata is what an object's metadata holds beside what every object carries.
type objectMetadata struct {
	// name is written as it is: a name the operator gave comes quoted.
	name string
	// clusterScoped is the Namespace, which is in no namespace.
	clusterScoped bool
	// component is the server the object belongs to, empty for an object both share.
	component string
	// labelsComment is written above the labels.
	labelsComment []string
	// labels and annotations are the object's own, written before the operator's, and
	// operatorLabels labels of its own the operator gave, the PodMonitor's.
	labels, annotations []keyValue
	operatorLabels      []keyValue
}

// writeMetadata writes an object's metadata: its name, its namespace, the labels, its own, the
// standard ones and the operator's, and the annotations, its own and the operator's.
func (c *Config) writeMetadata(sb *strings.Builder, m objectMetadata) {
	sb.WriteString("metadata:\n")
	fmt.Fprintf(sb, "  name: %s\n", m.name)
	if !m.clusterScoped {
		fmt.Fprintf(sb, "  namespace: %s\n", yamlQuote(c.K8sNamespace))
	}
	for _, line := range m.labelsComment {
		fmt.Fprintf(sb, "  # %s\n", line)
	}
	sb.WriteString("  labels:\n")
	writePairs(sb, "    ", slices.Concat(m.labels, c.standardLabels(m.component)))
	writeOperatorPairs(sb, "    ", slices.Concat(m.operatorLabels, c.Labels))
	if len(m.annotations)+len(c.Annotations) > 0 {
		sb.WriteString("  annotations:\n")
		writePairs(sb, "    ", m.annotations)
		writeOperatorPairs(sb, "    ", c.Annotations)
	}
}

// writePairs writes the manifest's own labels or annotations at indent, each value quoted, since a
// version or a namespace could read as a number or a boolean.
func writePairs(sb *strings.Builder, indent string, pairs []keyValue) {
	for _, pair := range pairs {
		fmt.Fprintf(sb, "%s%s: %s\n", indent, pair.key, yamlQuote(pair.value))
	}
}

// writeOperatorPairs writes labels or annotations the operator gave at indent, the key quoted too,
// since a key such as yes or 1 is a valid label key that YAML would read as no string.
func writeOperatorPairs(sb *strings.Builder, indent string, pairs []keyValue) {
	for _, pair := range pairs {
		fmt.Fprintf(sb, "%s%s: %s\n", indent, yamlQuote(pair.key), yamlQuote(pair.value))
	}
}

// askLabels asks the labels and annotations every object carries beside the standard labels, which
// an organisation's admission policies may require, none by default (#686 section 6).
func (w *wizard) askLabels() error {
	c := w.config
	if !w.interactive {
		c.Labels, c.Annotations = w.flags.Labels, w.flags.Annotations
		if err := c.checkPodMonitorLabels(); err != nil {
			return errs.Wrap(err, "invalid --labels")
		}
		if len(c.Labels) > 0 {
			w.out.info("Labels: %s", joinPairs(c.Labels))
		}
		if len(c.Annotations) > 0 {
			w.out.info("Annotations: %s", joinPairs(c.Annotations))
		}
		return nil
	}
	w.out.println("Every object carries the standard labels, app.kubernetes.io/name: goiabada and the")
	w.out.println("others. A cluster whose admission policies require labels or annotations of their own,")
	w.out.println("such as a team or a cost centre, refuses objects without them: name them here, and every")
	w.out.println("object and both pod templates carry them.")
	w.out.println()
	answer, err := w.validated("Labels (e.g., team=identity,cost-center=1234), blank for none", "", "labels", func(value string) error {
		labels, invalid := parseLabels(value)
		if invalid != nil {
			return invalid
		}
		return (&Config{Labels: labels, PodMonitorLabels: c.PodMonitorLabels}).checkPodMonitorLabels()
	})
	if err != nil {
		return err
	}
	c.Labels, _ = parseLabels(answer)
	answer, err = w.validated("Annotations (e.g., example.com/owner=identity-team), blank for none", "", "annotations", func(value string) error {
		_, invalid := parseAnnotations(value)
		return invalid
	})
	if err != nil {
		return err
	}
	c.Annotations, _ = parseAnnotations(answer)
	return nil
}

// checkPodMonitorLabels refuses a label the PodMonitor's own labels name too, which the PodMonitor
// would carry twice.
func (c *Config) checkPodMonitorLabels() error {
	for _, label := range c.Labels {
		if slices.ContainsFunc(c.PodMonitorLabels, func(own keyValue) bool { return own.key == label.key }) {
			return errs.Errorf("the label %s is one of the PodMonitor's labels too: give it in one of the two", label.key)
		}
	}
	return nil
}
