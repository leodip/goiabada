package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// replicasPrompt is the Kubernetes question on the auth server's replica count, two by default
// (#686 section 9).
const replicasPrompt = "Auth server replicas [2]: "

// validateReplicas takes a whole number of pods, one or more, spaces around it allowed.
func TestValidateReplicas(t *testing.T) {
	for _, value := range []string{"1", "2", " 3 ", "10"} {
		if err := validateReplicas(value); err != nil {
			t.Errorf("validateReplicas(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "0", "-1", "two", "1.5", "2 pods"} {
		if err := validateReplicas(value); err == nil {
			t.Errorf("validateReplicas(%q) accepted it", value)
		}
	}
}

// Kubernetes asks how many auth server pods run, two by default, asking again for an answer that is
// no count, and --authserver-replicas answers without a prompt, two when left out. The auth
// server's Deployment runs that many and the admin console's one, the answers file records the
// count, and the completion message gives the database connections the pods and the surge pod may
// open, each pod's pool of 20 times one more pod than the count, with room for stopping pods.
func TestWizard_AsksTheAuthServerReplicas(t *testing.T) {
	invalidFirst := withKubernetesAnswer(t, replicasPrompt, "0")
	for i := range invalidFirst {
		if invalidFirst[i].prompt == replicasPrompt {
			invalidFirst = append(invalidFirst[:i+1], append([]scriptedStep{{prompt: replicasPrompt, answer: "1"}}, invalidFirst[i+1:]...)...)
			break
		}
	}
	byFlag := func(replicas int) *CLIFlags {
		f := kubernetesFlags()
		f.AuthServerReplicas = replicas
		return f
	}
	cases := map[string]struct {
		flags       *CLIFlags
		steps       []scriptedStep
		want        int
		connections string
	}{
		"prompted, the default":   {&CLIFlags{}, withKubernetesAnswer(t, replicasPrompt, ""), 2, "(2 + 1) × 20 = 60"},
		"prompted, three":         {&CLIFlags{}, withKubernetesAnswer(t, replicasPrompt, "3"), 3, "(3 + 1) × 20 = 80"},
		"prompted, invalid first": {&CLIFlags{}, invalidFirst, 1, "(1 + 1) × 20 = 40"},
		"by flag, left out":       {byFlag(0), nil, 2, "(2 + 1) × 20 = 60"},
		"by flag, five":           {byFlag(5), nil, 5, "(5 + 1) × 20 = 120"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.AuthServerReplicas != tc.want {
				t.Errorf("AuthServerReplicas is %d, want %d", w.config.AuthServerReplicas, tc.want)
			}
			deployments := writtenDocuments(t, w)["Deployment"]
			for name, want := range map[string]int{"goiabada-authserver": tc.want, "goiabada-adminconsole": 1} {
				if got := atPath(deployments[name], "spec", "replicas"); got != want {
					t.Errorf("the Deployment %s runs %v replicas, want %d", name, got, want)
				}
			}
			said := strings.Join(strings.Fields(out.String()), " ")
			if !strings.Contains(said, tc.connections) || !strings.Contains(said, "beside the pods a rollout is still stopping") {
				t.Errorf("the completion message does not give the connections, %s, and room for stopping pods:\n%s", tc.connections, out)
			}
			answers, err := os.ReadFile(w.paths.answers)
			if err != nil {
				t.Fatal(err)
			}
			if want := fmt.Sprintf("\nauthserver-replicas: %d\n", tc.want); !strings.Contains(string(answers), want) {
				t.Errorf("the answers file does not record %q:\n%s", strings.TrimSpace(want), answers)
			}
			if name == "prompted, invalid first" && !strings.Contains(out.String(), "Invalid replicas") {
				t.Errorf("the invalid answer was not refused:\n%s", out)
			}
		})
	}

	t.Run("a negative flag is refused", func(t *testing.T) {
		w, _, out, _ := testWizard(t, byFlag(-1), nil)
		if err := w.setup(); err == nil || !strings.Contains(err.Error(), "--authserver-replicas") {
			t.Errorf("setup: %v, want --authserver-replicas refused\n%s", err, out)
		}
	})
	t.Run("ignored outside Kubernetes", func(t *testing.T) {
		w, _, out, _ := testWizard(t, &CLIFlags{DeploymentType: "production", DBType: "postgres", AuthServerURL: "https://auth.example.org", AuthServerReplicas: 3}, nil)
		if err := w.setup(); err != nil {
			t.Fatalf("setup: %v\n%s", err, out)
		}
		if w.config.AuthServerReplicas != 0 {
			t.Errorf("production holds AuthServerReplicas %d", w.config.AuthServerReplicas)
		}
	})
}

// The comment above each Deployment's replicas says what the count does: at one auth server pod a
// node drain stops sign-ins, from two it keeps them up, and the admin console runs one, since two
// pods can spend one administrator's refresh token at once.
func TestKubernetesManifest_TheReplicasSayWhatTheyDo(t *testing.T) {
	for replicas, said := range map[int]string{
		1: "# At one, a node drain stops sign-ins until the replacement is ready.\n  replicas: 1\n",
		2: "# From two, a node drain keeps sign-ins up, evicting one pod at a time.\n  replicas: 2\n",
		4: "# From two, a node drain keeps sign-ins up, evicting one pod at a time.\n  replicas: 4\n",
	} {
		config := goldenConfig(deploymentKubernetes, "postgres")
		config.AuthServerReplicas = replicas
		manifest := generateKubernetesManifests(config, outputPaths{})
		if !strings.Contains(manifest, said) {
			t.Errorf("at %d replicas the auth server's Deployment does not carry %q", replicas, said)
		}
		if !strings.Contains(manifest, "unless the gateway keeps each browser on one pod: see the High availability page.\n  replicas: 1\n") {
			t.Errorf("at %d replicas the admin console's Deployment does not say why it runs one pod", replicas)
		}
	}
}

// A run under --keep-secrets, which may change the count, has the operator check the database takes
// the connections before applying the manifest, as a first install's notes do.
func TestRegeneratedMessage_ChecksTheConnectionsBeforeTheApply(t *testing.T) {
	config := kubernetesConfig()
	config.KeepSecrets, config.AuthServerReplicas = true, 3
	var buf strings.Builder
	printRegeneratedMessage(&console{w: &buf}, config, config.Deployment.defaultPaths())
	out := strings.Join(strings.Fields(buf.String()), " ")
	sum := strings.Index(out, "2. The auth server's 3 pods, and the one more a rollout starts, each open up to 20 database connections: (3 + 1) × 20 = 80.")
	apply := strings.Index(out, "3. Apply the manifest alone")
	if sum < 0 || apply < 0 || sum > apply {
		t.Errorf("the message does not give the connections before the apply:\n%s", buf.String())
	}
}
