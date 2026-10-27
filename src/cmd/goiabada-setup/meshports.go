package main

import (
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// portList is --mesh-ports: port numbers separated by commas, in the order given.
type portList []int

// String is the ports as the summary reports them, separated by commas. A nil receiver is no port,
// because the flag package may call String on one.
func (p *portList) String() string {
	if p == nil {
		return ""
	}
	return joinPorts(*p)
}

// Set reads the ports with parseMeshPorts, whose refusal the flag package reports naming the flag.
func (p *portList) Set(value string) error {
	ports, err := parseMeshPorts(value)
	*p = ports
	return err
}

// parseMeshPorts reads port numbers separated by commas, refusing one that is no TCP port and one
// given twice.
func parseMeshPorts(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var ports []int
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		port, err := strconv.Atoi(field)
		if err != nil || port < 1 || port > 65535 {
			return nil, errs.Errorf("%q is not a port, a number from 1 to 65535", field)
		}
		if slices.Contains(ports, port) {
			return nil, errs.Errorf("port %d is given twice", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// joinPorts writes ports separated by commas, as they are read.
func joinPorts(ports []int) string {
	written := make([]string, 0, len(ports))
	for _, port := range ports {
		written = append(written, strconv.Itoa(port))
	}
	return strings.Join(written, ", ")
}

// askMeshPorts asks the ports a service mesh's proxies deliver on between meshed pods, which the
// NetworkPolicies admit from the same sources as each server's own port, none by default: Istio's
// ambient mode delivers on 15008 and Linkerd on 4143, where a policy admitting the server's port
// alone refuses the admin console's calls to the auth server, while Istio's sidecars keep the
// server's port between themselves (#686 section 8).
func (w *wizard) askMeshPorts() error {
	w.out.println()
	w.out.println("A service mesh's proxies may deliver traffic between meshed pods on a port of their own,")
	w.out.println("which the NetworkPolicies must admit too, or the admin console cannot reach the auth")
	w.out.println("server: 15008 under Istio's ambient mode, 4143 under Linkerd. Between Istio's sidecars,")
	w.out.println("each server's port is kept and none is needed; a sidecar called from ambient pods needs")
	w.out.println("15008.")
	answer, err := w.validated("Service mesh ports (e.g., 15008), blank for none", "", "ports", func(value string) error {
		_, invalid := parseMeshPorts(value)
		return invalid
	})
	if err != nil {
		return err
	}
	w.config.MeshPorts, _ = parseMeshPorts(answer)
	return nil
}

// meshPortsComment is what a NetworkPolicy's comment adds when its first rule admits the mesh's
// ports beside the server's: that a meshed caller reaches every port of the pod through them, a
// scraper in the mesh included, which the scraper's rule then does not admit, and that Istio's
// ambient mode sends the kubelet's probes from an address some CNIs check (#686 section 8).
func (c *Config) meshPortsComment() []string {
	if len(c.MeshPorts) == 0 {
		return nil
	}
	ports := "port " + joinPorts(c.MeshPorts)
	if n := len(c.MeshPorts); n > 1 {
		ports = "ports " + joinPorts(c.MeshPorts[:n-1]) + " and " + strconv.Itoa(c.MeshPorts[n-1])
	}
	comment := []string{
		"It admits the same sources to " + ports + " too, where your service mesh's proxies",
		"deliver between meshed pods. A meshed caller reaches every port of the pod that way, so",
		"the mesh's own authorization, not this policy, decides which ports it reaches.",
	}
	if c.admitsMetricsScraper() {
		comment = append(comment,
			"A scraper in the mesh arrives on the mesh's port too, which the scraper's rule below",
			"does not admit: keep it out of the mesh, or add that port to the rule.")
	}
	return append(comment,
		"Under Istio's ambient mode, the kubelet's probes come from 169.254.7.127 instead of the",
		"node, which some CNIs check against this policy: if the pods never turn ready, admit",
		"that address with an ipBlock.")
}
