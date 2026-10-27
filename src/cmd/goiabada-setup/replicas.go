package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// defaultAuthServerReplicas is the auth server's replica count when none is asked for: two, the
// fewest at which its PodDisruptionBudget keeps a pod serving through a node drain (#686 section 9).
const defaultAuthServerReplicas = 2

// authServerPoolSize is the most database connections one auth server pod opens, the default of
// GOIABADA_DB_MAX_OPEN_CONNS, which the manifest leaves unset.
const authServerPoolSize = 20

// highAvailabilityDocsURL is the page on running more than one pod of each server.
const highAvailabilityDocsURL = "https://goiabada.dev/deploy/kubernetes/high-availability/"

// validateReplicas refuses a replica count that is no whole number of pods, or none.
func validateReplicas(value string) error {
	replicas, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || replicas < 1 {
		return errs.Errorf("%q is not a number of replicas, 1 or more", value)
	}
	return nil
}

// connectionBudget is the database connections the auth server's running pods may open: each
// replica's pool, and the surge pod's, which a rollout starts before it stops an old one. Pods a
// rollout is still stopping hold their pools beyond it until they exit (#686 section 9).
func (c *Config) connectionBudget() int {
	return (c.AuthServerReplicas + 1) * authServerPoolSize
}

// askReplicas asks how many auth server pods run, two by default, saying what a node drain does to
// one and what each costs the database. The admin console runs one, which the question says, since
// two of its pods can spend one administrator's refresh token at once (#686 section 9).
func (w *wizard) askReplicas() error {
	c := w.config
	if !w.interactive {
		c.AuthServerReplicas = w.flags.AuthServerReplicas
		if c.AuthServerReplicas == 0 {
			c.AuthServerReplicas = defaultAuthServerReplicas
		}
		if err := validateReplicas(strconv.Itoa(c.AuthServerReplicas)); err != nil {
			return errs.Wrap(err, "invalid --authserver-replicas")
		}
		w.out.info("Auth server replicas: %d", c.AuthServerReplicas)
		return nil
	}
	w.out.println("The auth server's pods share the database, so it can run several. From two, a node drain")
	w.out.println("or upgrade keeps sign-ins up: its PodDisruptionBudget evicts one pod at a time. At one,")
	w.out.println("sign-ins stop until the replacement is ready.")
	w.out.printf("Each pod opens up to %d database connections, and a rollout runs one more pod, so the\n", authServerPoolSize)
	w.out.printf("database must accept (replicas + 1) × %d, beside the pods a rollout is still stopping and\n", authServerPoolSize)
	w.out.println("everything else it serves.")
	w.out.println("The admin console runs one pod; more need session affinity at the gateway:")
	w.out.println(highAvailabilityDocsURL)
	w.out.println()
	answer, err := w.validated("Auth server replicas", strconv.Itoa(defaultAuthServerReplicas), "replicas", validateReplicas)
	if err != nil {
		return err
	}
	c.AuthServerReplicas, _ = strconv.Atoi(strings.TrimSpace(answer))
	return nil
}

// replicasComment is the comment above a Deployment's replicas: for the auth server, what a pod
// costs the database and what its count does to a node drain; for the admin console, why it runs
// one.
func (c *Config) replicasComment(name string) []string {
	if name != "goiabada-authserver" {
		return []string{
			"One pod. With more, two can spend one administrator's refresh token at once, which signs",
			"them out, unless the gateway keeps each browser on one pod: see the High availability page.",
		}
	}
	drain := "From two, a node drain keeps sign-ins up, evicting one pod at a time."
	if c.AuthServerReplicas == 1 {
		drain = "At one, a node drain stops sign-ins until the replacement is ready."
	}
	return []string{
		fmt.Sprintf("Each pod opens up to GOIABADA_DB_MAX_OPEN_CONNS database connections, %d unless set.", authServerPoolSize),
		drain,
	}
}
