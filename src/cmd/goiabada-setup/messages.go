package main

import (
	"path/filepath"
	"strings"
)

func printBanner(out *console) {
	out.printf("%s================================================================================\n", out.cyan)
	out.printf("                         GOIABADA SETUP WIZARD v%s\n", version)
	out.printf("================================================================================%s\n", out.reset)
	out.println()
	out.println("This wizard will help you set up Goiabada by generating configuration files")
	out.println("with all credentials pre-configured.")
	out.println()
}

func printSummary(out *console, config *Config) {
	out.printf("%s%s================== Configuration Summary ==================%s\n", out.bold, out.cyan, out.reset)
	out.println()
	out.printf("  Deployment:       %s\n", config.Deployment.displayName)
	out.printf("  Database:         %s\n", config.Engine.name)
	out.printf("  Auth Server URL:  %s\n", config.AuthServerURL)
	out.printf("  Admin Console:    %s\n", config.AdminConsoleURL)
	if config.K8sNamespace != "" {
		out.printf("  K8s Namespace:    %s\n", config.K8sNamespace)
	}
	if config.Deployment.servedByEnvoyGateway {
		out.printf("  Traffic policy:   %s\n", config.GatewayTrafficPolicy)
		if config.NetworkPolicy {
			out.println("  NetworkPolicies:  admit only Envoy and the admin console")
		} else {
			out.println("  NetworkPolicies:  none")
		}
	}
	if config.Deployment.asksLocalProxy {
		if config.LocalProxy {
			out.println("  Reverse proxy:    on this machine (listen on 127.0.0.1)")
		} else {
			out.println("  Reverse proxy:    none (HTTPS served by Goiabada)")
		}
	}
	if config.Deployment.asksRateLimiter {
		if config.RateLimiter {
			out.println("  Rate limiter:     on")
		} else {
			out.println("  Rate limiter:     off")
		}
	}
	out.printf("  Admin Email:      %s\n", config.AdminEmail)
	out.printf("  Admin Password:   %s\n", maskPassword(config.AdminPassword))
	if config.DBHost != "" {
		out.printf("  DB Host:          %s:%s\n", config.DBHost, config.DBPort)
		out.printf("  DB Name:          %s\n", config.DBName)
		out.printf("  DB Username:      %s\n", config.DBUsername)
	}
	out.println()
	out.printf("%s%s==========================================================%s\n", out.bold, out.cyan, out.reset)
}

func printCompletionMessage(out *console, config *Config, outputPath string) {
	out.println()
	out.printf("%s%s================================================================================\n", out.bold, out.green)
	out.printf("                            SETUP COMPLETE!\n")
	out.printf("================================================================================%s\n", out.reset)
	out.println()

	config.Deployment.printInstructions(out, config, outputPath)

	out.println()
	out.println("URLs:")
	out.printf("    Auth Server:   %s%s%s\n", out.cyan, config.AuthServerURL, out.reset)
	out.printf("    Admin Console: %s%s%s\n", out.cyan, config.AdminConsoleURL, out.reset)
	out.println()
	out.printf("Login with: %s%s%s / %s\n", out.bold, config.AdminEmail, out.reset, config.AdminPassword)
	out.println()
	if config.AdminPassword == "changeme" || len(config.AdminPassword) < 8 {
		out.warning("Change the default password after first login!")
		out.println()
	}
}

func printKubernetesInstructions(out *console, config *Config, outputPath string) {
	out.println("To deploy Goiabada to Kubernetes:")
	out.println()
	out.printf("    %skubectl apply -f %s%s\n", out.cyan, filepath.Base(outputPath), out.reset)
	out.println()
	// A release build stamps its version as the tag; only a source build reaches here with latest
	// (#396 decision 10).
	if imageTag == "latest" {
		out.warning("The manifest follows the moving image tag \"latest\", so pods can run different releases")
		out.println("   and each start pulls whatever release it names then. Replace latest with a release")
		out.println("   version in both image lines to pin them.")
		out.println()
	}

	out.printf("%s%sPREREQUISITES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("Before deploying, ensure you have:")
	out.println()
	out.println("  1. Envoy Gateway installed, which brings the Gateway API CRDs:")
	out.printf("     %skubectl apply --server-side -f https://github.com/envoyproxy/gateway/releases/download/v1.9.1/install.yaml%s\n", out.cyan, out.reset)
	out.println("     (Check https://github.com/envoyproxy/gateway/releases for latest version)")
	out.println()
	out.println("     Wait for it to be ready:")
	out.printf("     %skubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available%s\n", out.cyan, out.reset)
	out.println()
	printEnvoyProxyPrerequisite(out, config.GatewayTrafficPolicy)
	out.println("     ---")
	out.println("     apiVersion: gateway.networking.k8s.io/v1")
	out.println("     kind: GatewayClass")
	out.println("     metadata:")
	out.println("       name: eg")
	out.println("     spec:")
	out.println("       controllerName: gateway.envoyproxy.io/gatewayclass-controller")
	out.println("       parametersRef:")
	out.println("         group: gateway.envoyproxy.io")
	out.println("         kind: EnvoyProxy")
	out.println("         name: goiabada-proxy")
	out.println("         namespace: envoy-gateway-system")
	out.println()
	out.printf("     %skubectl apply -f gatewayclass.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("     The EnvoyProxy and the GatewayClass are cluster-wide: on a cluster that already runs")
	out.println("     Envoy Gateway, the traffic policy belongs to whoever runs it, so agree it with them")
	out.println("     rather than apply these over theirs.")
	out.println()
	out.println("  3. cert-manager for automatic TLS certificates, with Gateway API support on:")
	out.printf("     %skubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager patch deployment cert-manager --type=json -p='[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--enable-gateway-api\"}]'%s\n", out.cyan, out.reset)
	out.println("     (Install it after Envoy Gateway: cert-manager looks for the Gateway API CRDs at startup)")
	out.println()
	out.println("     Wait for it to be ready:")
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager --timeout=5m%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=5m%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=5m%s\n", out.cyan, out.reset)
	out.println()
	out.println("  4. A ClusterIssuer solving HTTP-01 through the Gateway (save as letsencrypt-issuer.yaml):")
	out.println("     ---")
	out.println("     apiVersion: cert-manager.io/v1")
	out.println("     kind: ClusterIssuer")
	out.println("     metadata:")
	out.println("       name: letsencrypt-prod")
	out.println("     spec:")
	out.println("       acme:")
	out.println("         server: https://acme-v02.api.letsencrypt.org/directory")
	out.println("         email: <your-email>")
	out.println("         privateKeySecretRef:")
	out.println("           name: letsencrypt-prod")
	out.println("         solvers:")
	out.println("         - http01:")
	out.println("             gatewayHTTPRoute:")
	out.println("               parentRefs:")
	out.println("               - name: goiabada")
	out.printf("                 namespace: %s\n", config.K8sNamespace)
	out.println("                 kind: Gateway")
	out.println()
	out.printf("     %skubectl apply -f letsencrypt-issuer.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("  5. DNS records pointing to the Gateway's address:")
	out.println("     After deploying, get the address:")
	out.printf("     %skubectl get gateway goiabada -n %s -o jsonpath='{.status.addresses[0].value}'%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("     %s<auth-host>  -> <Gateway-address>%s\n", out.cyan, out.reset)
	out.printf("     %s<admin-host> -> <Gateway-address>%s\n", out.cyan, out.reset)
	out.println()
	out.println("     The generated Gateway already has cert-manager annotation enabled.")
	out.println("     Remove it if you prefer to manage TLS certificates manually.")
	out.println()

	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The database must be empty for a fresh deployment. Goiabada will")
	out.println("    automatically seed the database with initial data including the")
	out.println("    admin user and OAuth clients configured with the URLs above.")
	out.println("    If redeploying with different URLs, use a fresh database.")
	out.println()
	out.println("  • If using a managed database service (Supabase, PlanetScale, etc.),")
	out.println("    use the connection pooler endpoint for better compatibility (IPv4).")
	out.println()

	out.printf("%s%sTROUBLESHOOTING TIPS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • If cert-manager HTTP-01 challenges fail or timeout:")
	out.println("    - Verify DNS records point to the Gateway's address")
	out.println("    - Ensure port 80 is accessible from the internet")
	if config.GatewayTrafficPolicy == trafficPolicyLocal {
		out.println("    - Under Local, a node with no Envoy pod drops the load balancer's traffic: check")
		out.println("      the EnvoyProxy in step 2 is applied and runs an Envoy pod on every node:")
		out.printf("      %skubectl get daemonset -n envoy-gateway-system%s\n", out.cyan, out.reset)
		out.println("    - If your load balancer still cannot reach Envoy, use the Cluster policy instead:")
		out.println("      the EnvoyProxy the wizard prints with --gateway-traffic-policy=cluster, which has")
		out.println("      no envoyDaemonSet. Goiabada then sees a node's address for every client.")
	} else {
		out.println("    - If the GatewayClass has no EnvoyProxy with externalTrafficPolicy: Cluster,")
		out.println("      apply the one in step 2 above")
	}
	out.println()
	if config.NetworkPolicy {
		out.println("  • A connection a NetworkPolicy refuses times out rather than being refused. If a")
		out.println("    workload cannot reach a server, check what the policies admit:")
		out.printf("      %skubectl describe networkpolicy -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
		out.println()
	}
	out.println("  • Check Gateway and route status:")
	out.printf("      %skubectl get gateway,httproute -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("      %skubectl describe gateway goiabada -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Check certificates:")
	out.printf("      %skubectl get certificates -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Verify pods are running:")
	out.printf("      %skubectl get pods -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Check pod logs for errors:")
	out.printf("      %skubectl logs -n %s deployment/goiabada-authserver%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
}

// printEnvoyProxyPrerequisite prints the opening of the completion message's second prerequisite,
// the EnvoyProxy setting the traffic policy chosen, down to the GatewayClass that follows it: under
// Cluster, Envoy stays a Deployment; under Local it runs on every node as a DaemonSet, so no node
// the load balancer sends to drops the traffic (#396 decision 4). envoyDaemonSet, envoyService and
// externalTrafficPolicy are Envoy Gateway v1.9.1's (api/v1alpha1), which admits one of
// envoyDeployment and envoyDaemonSet, and reads an empty envoyDaemonSet as every default.
func printEnvoyProxyPrerequisite(out *console, policy trafficPolicy) {
	if policy == trafficPolicyLocal {
		out.println("  2. The GatewayClass the manifest names, with externalTrafficPolicy: Local and Envoy")
		out.println("     on every node as a DaemonSet, so Goiabada sees each client's address and no node")
		out.println("     drops the load balancer's traffic (save as gatewayclass.yaml):")
	} else {
		out.println("  2. The GatewayClass the manifest names, with externalTrafficPolicy: Cluster")
		out.println("     for better compatibility (save as gatewayclass.yaml):")
	}
	out.println("     ---")
	out.println("     apiVersion: gateway.envoyproxy.io/v1alpha1")
	out.println("     kind: EnvoyProxy")
	out.println("     metadata:")
	out.println("       name: goiabada-proxy")
	out.printf("       namespace: %s\n", envoyProxyNamespace)
	out.println("     spec:")
	out.println("       provider:")
	out.println("         type: Kubernetes")
	out.println("         kubernetes:")
	if policy == trafficPolicyLocal {
		out.println("           envoyDaemonSet: {}")
	}
	out.println("           envoyService:")
	out.printf("             externalTrafficPolicy: %s\n", policy)
}

func printNativeInstructions(out *console, config *Config, outputPath string) {
	out.println("To run Goiabada with native binaries:")
	out.println()
	out.printf("%s%s1. DOWNLOAD BINARIES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  Download the pre-built binaries for your platform from:")
	out.printf("  %shttps://github.com/leodip/goiabada/releases%s\n", out.cyan, out.reset)
	out.println()
	out.println("  Extract the binaries:")
	out.printf("  %star -xzf goiabada-<version>-<os>-<arch>.tar.gz%s\n", out.cyan, out.reset)
	out.println()
	out.printf("%s%s2. START THE SERVERS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  Load the environment and start both servers (in separate terminals):")
	out.println()
	out.println("  Auth server:")
	out.printf("  %sset -a && . ./%s && set +a && ./goiabada-authserver%s\n", out.cyan, filepath.Base(outputPath), out.reset)
	out.println()
	out.println("  Admin console:")
	out.printf("  %sset -a && . ./%s && set +a && ./goiabada-adminconsole%s\n", out.cyan, filepath.Base(outputPath), out.reset)
	out.println()
	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The environment file contains sensitive secrets. Keep it secure!")
	out.println()
	if config.LocalProxy {
		out.println("  • Both servers listen on 127.0.0.1 alone. Point your reverse proxy at")
		out.println("    http://127.0.0.1:9090 (auth server) and http://127.0.0.1:9091 (admin console),")
		out.println("    and have it set X-Forwarded-For and X-Forwarded-Proto.")
	} else {
		out.println("  • Both servers listen on every interface and serve plain HTTP until you set")
		out.printf("    their CERTFILE and KEYFILE in %s, as its comments say.\n", filepath.Base(outputPath))
	}
	out.println()
	out.println("  • The database must be empty for a fresh deployment. Goiabada will")
	out.println("    automatically seed the database with initial data including the")
	out.println("    admin user and OAuth clients configured with the URLs above.")
	out.println()
	out.println("  • For production, consider using a process manager like systemd")
	out.println("    to keep the services running and restart them on failure.")
	out.println()
}

func printComposeInstructions(out *console, _ *Config, _ string) {
	out.println("To start Goiabada, run:")
	out.println()
	out.printf("    %sdocker compose up -d%s\n", out.cyan, out.reset)
	out.println()
	out.println("Then access:")
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
