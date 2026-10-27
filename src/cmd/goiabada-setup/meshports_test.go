package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// meshPortsPrompt is the question asked after the namespace the NetworkPolicies admit, none by
// default (#686 section 8).
const meshPortsPrompt = "Service mesh ports (e.g., 15008), blank for none: "

// parseMeshPorts reads ports separated by commas, spaces around them allowed, and refuses one that is
// no TCP port or is given twice.
func TestParseMeshPorts(t *testing.T) {
	for input, want := range map[string][]int{
		"":              nil,
		" ":             nil,
		"15008":         {15008},
		"15008, 4143":   {15008, 4143},
		"4143,15008":    {4143, 15008},
		" 1 ,65535 ":    {1, 65535},
		"15008,4143,80": {15008, 4143, 80},
	} {
		got, err := parseMeshPorts(input)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseMeshPorts(%q) = %v, %v, want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"0", "65536", "-1", "http", "15008,", "15008;4143", "15008,15008", "15008 4143"} {
		if got, err := parseMeshPorts(input); err == nil {
			t.Errorf("parseMeshPorts(%q) = %v, want it refused", input, got)
		}
	}
}

// With the NetworkPolicies on, the service mesh's ports are asked, none by default, asking again for
// an answer that is no port list, and --mesh-ports answers without a prompt; with them off it is not
// read. The first rule of both policies admits the ports beside the server's, from the same
// sources, and the second, the scraper's, admits none of them; the comments say so, and what
// that opens and closes under a mesh (#686 section 8).
func TestWizard_NetworkPoliciesAdmitTheServiceMeshPorts(t *testing.T) {
	prompted := func(answers ...string) []scriptedStep {
		steps := withAnswers(t, deploymentKubernetes, map[string]string{networkPolicyPrompt: "y", metricsPrompt: "2"})
		at := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == meshPortsPrompt })
		steps[at].answer = answers[0]
		for _, answer := range answers[1:] {
			at++
			steps = slices.Insert(steps, at, scriptedStep{prompt: meshPortsPrompt, answer: answer})
		}
		metrics := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == metricsPrompt })
		return slices.Insert(steps, metrics+1, scriptedStep{prompt: metricsNamespacePrompt, answer: ""})
	}
	byFlag := func(networkPolicy bool, ports ...int) *CLIFlags {
		f := kubernetesFlags()
		f.NetworkPolicy, f.MeshPorts, f.Metrics = networkPolicy, ports, metricsAnnotations
		return f
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  []int
	}{
		"prompted, the default":       {&CLIFlags{}, prompted(""), nil},
		"prompted, two":               {&CLIFlags{}, prompted("15008, 4143"), []int{15008, 4143}},
		"prompted, invalid first":     {&CLIFlags{}, prompted("15008,http", "4143"), []int{4143}},
		"by flag, left out":           {byFlag(true), nil, nil},
		"by flag, two":                {byFlag(true, 15008, 4143), nil, []int{15008, 4143}},
		"by flag, no NetworkPolicies": {byFlag(false, 15008), nil, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if !slices.Equal(w.config.MeshPorts, tc.want) {
				t.Errorf("MeshPorts is %v, want %v", w.config.MeshPorts, tc.want)
			}
			if name == "prompted, invalid first" && !strings.Contains(out.String(), `"http" is not a port`) {
				t.Errorf("the invalid answer was not refused:\n%s", out)
			}
			for name, server := range map[string]int{"goiabada-authserver": 9090, "goiabada-adminconsole": 9091} {
				policy, found := writtenDocuments(t, w)["NetworkPolicy"][name]
				if !found {
					if tc.flags.NetworkPolicy || tc.steps != nil {
						t.Errorf("there is no NetworkPolicy %s", name)
					}
					continue
				}
				rules := listAt(policy, "spec", "ingress")
				if got, want := admittedPorts(rules[0]), slices.Concat([]int{server}, tc.want); !slices.Equal(got, want) {
					t.Errorf("the NetworkPolicy %s's first rule admits %v, want %v", name, got, want)
				}
				if got := admittedPorts(rules[1]); len(got) != 1 || slices.Contains(tc.want, got[0]) {
					t.Errorf("the NetworkPolicy %s's scraper rule admits %v, want the metrics port alone", name, got)
				}
			}
			written := readFile(t, w.paths.description)
			if said := "It admits the same sources to ports 15008 and 4143 too"; slices.Equal(tc.want, []int{15008, 4143}) &&
				strings.Count(written, said) != 2 {
				t.Errorf("the policies' comments do not both say %q", said)
			}
			// Every case exposes metrics, so a policy admitting mesh ports also says what they open
			// to meshed callers, what a scraper in the mesh needs, and where ambient's probes come
			// from, as does the completion message for the scraper.
			for _, said := range []string{
				"A meshed caller reaches every port of the pod that way",
				"A scraper in the mesh arrives on the mesh's port too",
				"the kubelet's probes come from 169.254.7.127",
			} {
				if want := map[bool]int{true: 2, false: 0}[len(tc.want) > 0]; strings.Count(written, said) != want {
					t.Errorf("%d of the manifest's comments say %q, want %d", strings.Count(written, said), said, want)
				}
			}
			if got := strings.Contains(out.String(), "A scraper in the service mesh arrives on the mesh's port"); got != (len(tc.want) > 0) {
				t.Errorf("the completion message warns of a scraper in the mesh: %v, want %v", got, len(tc.want) > 0)
			}
			if len(tc.want) == 0 && strings.Contains(written, "service mesh") {
				t.Error("a manifest admitting no mesh port mentions a service mesh")
			}
		})
	}
}

// admittedPorts is the ports one NetworkPolicy ingress rule admits, in order.
func admittedPorts(rule any) []int {
	var ports []int
	for _, port := range listAt(rule, "ports") {
		ports = append(ports, atPath(port, "port").(int))
	}
	return ports
}
