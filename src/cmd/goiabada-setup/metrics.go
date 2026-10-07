package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// metricsExposure is how a scraper discovers the servers' metrics listeners, as --metrics spells
// it. Which one works depends on the cluster: the prometheus.io annotations are a convention the
// prometheus-community prometheus chart honors by default and kube-prometheus-stack ignores, and a
// PodMonitor needs the Prometheus Operator's CRDs (#400 decision 7).
type metricsExposure string

const (
	metricsNone        metricsExposure = "none"
	metricsAnnotations metricsExposure = "annotations"
	metricsPodMonitor  metricsExposure = "podmonitor"
)

// The metrics listeners' ports, each server's own default, which the manifest names as each
// container's metrics port rather than setting them (#400 decision 3).
const (
	authServerMetricsPort   = 9190
	adminConsoleMetricsPort = 9191
)

// defaultMetricsNamespace is the scraper namespace offered, kube-prometheus-stack's usual one.
const defaultMetricsNamespace = "monitoring"

// monitoringDocsURL is the page listing the metrics, how to scrape them and what to alert on.
const monitoringDocsURL = "https://goiabada.dev/deploy/monitoring/"

// String is the exposure as --metrics spells it, empty when the flag was left out.
func (m *metricsExposure) String() string {
	if m == nil {
		return ""
	}
	return string(*m)
}

// Set reads none, annotations or podmonitor in any case, and refuses anything else, which the flag
// package reports naming the flag.
func (m *metricsExposure) Set(value string) error {
	for _, exposure := range []metricsExposure{metricsNone, metricsAnnotations, metricsPodMonitor} {
		if strings.EqualFold(value, string(exposure)) {
			*m = exposure
			return nil
		}
	}
	return errs.New("use none, annotations or podmonitor")
}

// exposesMetrics says either yes answer was given, which turns both metrics listeners on.
func (c *Config) exposesMetrics() bool {
	return c.Metrics == metricsAnnotations || c.Metrics == metricsPodMonitor
}

// admitsMetricsScraper says the NetworkPolicies are on and must admit the scraper's namespace to the
// metrics ports (#400 decision 8).
func (c *Config) admitsMetricsScraper() bool {
	return c.NetworkPolicy && c.exposesMetrics()
}

// metricsAnswer is the answer as the summary and a non-interactive run report it.
func (c *Config) metricsAnswer() string {
	switch c.Metrics {
	case metricsAnnotations:
		return "pod annotations"
	case metricsPodMonitor:
		if len(c.PodMonitorLabels) == 0 {
			return "a PodMonitor, unlabeled"
		}
		return "a PodMonitor labeled " + podMonitorLabels(c.PodMonitorLabels).String()
	}
	return "none"
}

// podMonitorLabel is one label the PodMonitor carries, for the Prometheus that selects it.
type podMonitorLabel struct{ key, value string }

// podMonitorLabels is --podmonitor-labels: key=value pairs separated by commas, in the order given.
type podMonitorLabels []podMonitorLabel

// String is the labels as the summary reports them, key=value separated by commas.
func (l podMonitorLabels) String() string {
	pairs := make([]string, 0, len(l))
	for _, label := range l {
		pairs = append(pairs, label.key+"="+label.value)
	}
	return strings.Join(pairs, ", ")
}

// Set reads the labels with parsePodMonitorLabels, whose refusal the flag package reports naming
// the flag.
func (l *podMonitorLabels) Set(value string) error {
	labels, err := parsePodMonitorLabels(value)
	*l = labels
	return err
}

// The label syntax Kubernetes accepts ("Labels and Selectors", syntax and character set): a name,
// and a value unless it is empty, of at most 63 characters, alphanumeric at both ends with dashes,
// underscores and dots between; a key's optional prefix is a DNS subdomain of at most 253.
var (
	labelNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	dnsSubdomain     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// parsePodMonitorLabels reads a label set written key=value, pairs separated by commas and spaces
// around either ignored, refusing a key or value Kubernetes would refuse and a key given twice.
// Blank is no label.
func parsePodMonitorLabels(value string) ([]podMonitorLabel, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var labels []podMonitorLabel
	seen := map[string]bool{}
	for _, pair := range strings.Split(value, ",") {
		key, labelValue, found := strings.Cut(pair, "=")
		key, labelValue = strings.TrimSpace(key), strings.TrimSpace(labelValue)
		if !found {
			return nil, errs.Errorf("%q is not key=value", strings.TrimSpace(pair))
		}
		if err := validateLabelKey(key); err != nil {
			return nil, err
		}
		if labelValue != "" && (len(labelValue) > 63 || !labelNamePattern.MatchString(labelValue)) {
			return nil, errs.Errorf("%q is not a label value: at most 63 letters, digits, '-', '_' and '.', starting and ending with a letter or digit", labelValue)
		}
		if seen[key] {
			return nil, errs.Errorf("the label %s is given twice", key)
		}
		seen[key] = true
		labels = append(labels, podMonitorLabel{key, labelValue})
	}
	return labels, nil
}

func validateLabelKey(key string) error {
	name := key
	if prefix, rest, found := strings.Cut(key, "/"); found {
		if len(prefix) > 253 || !dnsSubdomain.MatchString(prefix) {
			return errs.Errorf("%q is not a label key: its prefix, %q, is not a lowercase DNS subdomain", key, prefix)
		}
		name = rest
	}
	if len(name) > 63 || !labelNamePattern.MatchString(name) {
		return errs.Errorf("%q is not a label key: its name is at most 63 letters, digits, '-', '_' and '.', starting and ending with a letter or digit", key)
	}
	return nil
}

// exposedMetricsPort is the server's metrics port with either yes answer, and 0 with metrics off.
func (c *Config) exposedMetricsPort(port int) int {
	if !c.exposesMetrics() {
		return 0
	}
	return port
}

// annotatedMetricsPort is the port the pod template's prometheus.io annotations name, and 0 when the
// answer writes none.
func (c *Config) annotatedMetricsPort(port int) int {
	if c.Metrics != metricsAnnotations {
		return 0
	}
	return port
}

// metricsScraperComment is what a NetworkPolicy's comment adds when it admits the scraper's
// namespace to the server's metrics port.
func (c *Config) metricsScraperComment(metricsPort int) []string {
	if !c.admitsMetricsScraper() {
		return nil
	}
	return []string{
		fmt.Sprintf("The second rule admits the metrics scraper's namespace, %s, to the metrics port, %d,", c.MetricsNamespace, metricsPort),
		"and to nothing else. To admit a scraper in another namespace, add its namespaceSelector to",
		"that rule's from.",
	}
}
