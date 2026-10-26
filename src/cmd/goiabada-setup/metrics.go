package main

import (
	"fmt"
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
			return "a PodMonitor"
		}
		return "a PodMonitor labeled " + joinPairs(c.PodMonitorLabels)
	}
	return "none"
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
