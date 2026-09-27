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

	out.printf("%s%sPREREQUISITES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("Before deploying, ensure you have:")
	out.println()
	out.println("  1. ingress-nginx installed (with externalTrafficPolicy: Cluster for better compatibility):")
	out.printf("     %scurl -s https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.14.0/deploy/static/provider/cloud/deploy.yaml | sed 's/externalTrafficPolicy: Local/externalTrafficPolicy: Cluster/' | kubectl apply -f -%s\n", out.cyan, out.reset)
	out.println("     (Check https://github.com/kubernetes/ingress-nginx/releases for latest version)")
	out.println()
	out.println("     Wait for it to be ready:")
	out.printf("     %skubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s%s\n", out.cyan, out.reset)
	out.println()
	out.println("  2. cert-manager for automatic TLS certificates:")
	out.printf("     %skubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.1/cert-manager.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("     Wait for it to be ready:")
	out.printf("     %skubectl wait --namespace cert-manager --for=condition=ready pod --selector=app.kubernetes.io/instance=cert-manager --timeout=120s%s\n", out.cyan, out.reset)
	out.println()
	out.println("     Then create a ClusterIssuer (save as letsencrypt-issuer.yaml):")
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
	out.println("             ingress:")
	out.println("               class: nginx")
	out.println()
	out.printf("     %skubectl apply -f letsencrypt-issuer.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("  3. DNS records pointing to your LoadBalancer IP:")
	out.println("     After deploying, get the LoadBalancer IP:")
	out.printf("     %skubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'%s\n", out.cyan, out.reset)
	out.printf("     %s<auth-host>  -> <LoadBalancer-IP>%s\n", out.cyan, out.reset)
	out.printf("     %s<admin-host> -> <LoadBalancer-IP>%s\n", out.cyan, out.reset)
	out.println()
	out.println("     The generated manifest already has cert-manager annotation enabled.")
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
	out.println("    - Verify DNS records point to the LoadBalancer IP")
	out.println("    - Ensure port 80 is accessible from the internet")
	out.println("    - If you didn't use the install command above (with sed), patch the service:")
	out.printf("      %skubectl patch svc ingress-nginx-controller -n ingress-nginx -p '{\"spec\":{\"externalTrafficPolicy\":\"Cluster\"}}'%s\n", out.cyan, out.reset)
	out.println()
	out.println("  • Check Ingress status:")
	out.printf("      %skubectl get ingress -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("      %skubectl describe ingress -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
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

func printNativeInstructions(out *console, _ *Config, outputPath string) {
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
	out.printf("  %ssource %s && ./goiabada-authserver%s\n", out.cyan, filepath.Base(outputPath), out.reset)
	out.println()
	out.println("  Admin console:")
	out.printf("  %ssource %s && ./goiabada-adminconsole%s\n", out.cyan, filepath.Base(outputPath), out.reset)
	out.println()
	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The environment file contains sensitive secrets. Keep it secure!")
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
