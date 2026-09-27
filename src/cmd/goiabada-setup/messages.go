package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func printBanner() {
	fmt.Printf("%s================================================================================\n", colorCyan)
	fmt.Printf("                         GOIABADA SETUP WIZARD v%s\n", version)
	fmt.Printf("================================================================================%s\n", colorReset)
	fmt.Println()
	fmt.Println("This wizard will help you set up Goiabada by generating configuration files")
	fmt.Println("with all credentials pre-configured.")
	fmt.Println()
}

func printSummary(config *Config) {
	fmt.Printf("%s%s================== Configuration Summary ==================%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("  Deployment:       %s\n", config.Deployment.displayName)
	fmt.Printf("  Database:         %s\n", config.Engine.name)
	fmt.Printf("  Auth Server URL:  %s\n", config.AuthServerURL)
	fmt.Printf("  Admin Console:    %s\n", config.AdminConsoleURL)
	if config.K8sNamespace != "" {
		fmt.Printf("  K8s Namespace:    %s\n", config.K8sNamespace)
	}
	fmt.Printf("  Admin Email:      %s\n", config.AdminEmail)
	fmt.Printf("  Admin Password:   %s\n", maskPassword(config.AdminPassword))
	if config.DBHost != "" {
		fmt.Printf("  DB Host:          %s:%s\n", config.DBHost, config.DBPort)
		fmt.Printf("  DB Name:          %s\n", config.DBName)
		fmt.Printf("  DB Username:      %s\n", config.DBUsername)
	}
	fmt.Println()
	fmt.Printf("%s%s==========================================================%s\n", colorBold, colorCyan, colorReset)
}

func printCompletionMessage(config *Config, outputPath string) {
	fmt.Println()
	fmt.Printf("%s%s================================================================================\n", colorBold, colorGreen)
	fmt.Printf("                            SETUP COMPLETE!\n")
	fmt.Printf("================================================================================%s\n", colorReset)
	fmt.Println()

	config.Deployment.printInstructions(config, outputPath)

	fmt.Println()
	fmt.Println("URLs:")
	fmt.Printf("    Auth Server:   %s%s%s\n", colorCyan, config.AuthServerURL, colorReset)
	fmt.Printf("    Admin Console: %s%s%s\n", colorCyan, config.AdminConsoleURL, colorReset)
	fmt.Println()
	fmt.Printf("Login with: %s%s%s / %s\n", colorBold, config.AdminEmail, colorReset, config.AdminPassword)
	fmt.Println()
	if config.AdminPassword == "changeme" || len(config.AdminPassword) < 8 {
		printWarning("Change the default password after first login!")
		fmt.Println()
	}
}

func printKubernetesInstructions(config *Config, outputPath string) {
	fmt.Println("To deploy Goiabada to Kubernetes:")
	fmt.Println()
	fmt.Printf("    %skubectl apply -f %s%s\n", colorCyan, filepath.Base(outputPath), colorReset)
	fmt.Println()

	fmt.Printf("%s%sPREREQUISITES%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("Before deploying, ensure you have:")
	fmt.Println()
	fmt.Println("  1. ingress-nginx installed (with externalTrafficPolicy: Cluster for better compatibility):")
	fmt.Printf("     %scurl -s https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.14.0/deploy/static/provider/cloud/deploy.yaml | sed 's/externalTrafficPolicy: Local/externalTrafficPolicy: Cluster/' | kubectl apply -f -%s\n", colorCyan, colorReset)
	fmt.Println("     (Check https://github.com/kubernetes/ingress-nginx/releases for latest version)")
	fmt.Println()
	fmt.Println("     Wait for it to be ready:")
	fmt.Printf("     %skubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("  2. cert-manager for automatic TLS certificates:")
	fmt.Printf("     %skubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.1/cert-manager.yaml%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("     Wait for it to be ready:")
	fmt.Printf("     %skubectl wait --namespace cert-manager --for=condition=ready pod --selector=app.kubernetes.io/instance=cert-manager --timeout=120s%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("     Then create a ClusterIssuer (save as letsencrypt-issuer.yaml):")
	fmt.Println("     ---")
	fmt.Println("     apiVersion: cert-manager.io/v1")
	fmt.Println("     kind: ClusterIssuer")
	fmt.Println("     metadata:")
	fmt.Println("       name: letsencrypt-prod")
	fmt.Println("     spec:")
	fmt.Println("       acme:")
	fmt.Println("         server: https://acme-v02.api.letsencrypt.org/directory")
	fmt.Println("         email: <your-email>")
	fmt.Println("         privateKeySecretRef:")
	fmt.Println("           name: letsencrypt-prod")
	fmt.Println("         solvers:")
	fmt.Println("         - http01:")
	fmt.Println("             ingress:")
	fmt.Println("               class: nginx")
	fmt.Println()
	fmt.Printf("     %skubectl apply -f letsencrypt-issuer.yaml%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("  3. DNS records pointing to your LoadBalancer IP:")
	fmt.Println("     After deploying, get the LoadBalancer IP:")
	fmt.Printf("     %skubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'%s\n", colorCyan, colorReset)
	fmt.Printf("     %s<auth-host>  -> <LoadBalancer-IP>%s\n", colorCyan, colorReset)
	fmt.Printf("     %s<admin-host> -> <LoadBalancer-IP>%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("     The generated manifest already has cert-manager annotation enabled.")
	fmt.Println("     Remove it if you prefer to manage TLS certificates manually.")
	fmt.Println()

	fmt.Printf("%s%sIMPORTANT NOTES%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("  • The database must be empty for a fresh deployment. Goiabada will")
	fmt.Println("    automatically seed the database with initial data including the")
	fmt.Println("    admin user and OAuth clients configured with the URLs above.")
	fmt.Println("    If redeploying with different URLs, use a fresh database.")
	fmt.Println()
	fmt.Println("  • If using a managed database service (Supabase, PlanetScale, etc.),")
	fmt.Println("    use the connection pooler endpoint for better compatibility (IPv4).")
	fmt.Println()

	fmt.Printf("%s%sTROUBLESHOOTING TIPS%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("  • If cert-manager HTTP-01 challenges fail or timeout:")
	fmt.Println("    - Verify DNS records point to the LoadBalancer IP")
	fmt.Println("    - Ensure port 80 is accessible from the internet")
	fmt.Println("    - If you didn't use the install command above (with sed), patch the service:")
	fmt.Printf("      %skubectl patch svc ingress-nginx-controller -n ingress-nginx -p '{\"spec\":{\"externalTrafficPolicy\":\"Cluster\"}}'%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("  • Check Ingress status:")
	fmt.Printf("      %skubectl get ingress -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
	fmt.Printf("      %skubectl describe ingress -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
	fmt.Println()
	fmt.Println("  • Check certificates:")
	fmt.Printf("      %skubectl get certificates -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
	fmt.Println()
	fmt.Println("  • Verify pods are running:")
	fmt.Printf("      %skubectl get pods -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
	fmt.Println()
	fmt.Println("  • Check pod logs for errors:")
	fmt.Printf("      %skubectl logs -n %s deployment/goiabada-authserver%s\n", colorCyan, config.K8sNamespace, colorReset)
	fmt.Println()
}

func printNativeInstructions(_ *Config, outputPath string) {
	fmt.Println("To run Goiabada with native binaries:")
	fmt.Println()
	fmt.Printf("%s%s1. DOWNLOAD BINARIES%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("  Download the pre-built binaries for your platform from:")
	fmt.Printf("  %shttps://github.com/leodip/goiabada/releases%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("  Extract the binaries:")
	fmt.Printf("  %star -xzf goiabada-<version>-<os>-<arch>.tar.gz%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("%s%s2. START THE SERVERS%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("  Load the environment and start both servers (in separate terminals):")
	fmt.Println()
	fmt.Println("  Auth server:")
	fmt.Printf("  %ssource %s && ./goiabada-authserver%s\n", colorCyan, filepath.Base(outputPath), colorReset)
	fmt.Println()
	fmt.Println("  Admin console:")
	fmt.Printf("  %ssource %s && ./goiabada-adminconsole%s\n", colorCyan, filepath.Base(outputPath), colorReset)
	fmt.Println()
	fmt.Printf("%s%sIMPORTANT NOTES%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Println("  • The environment file contains sensitive secrets. Keep it secure!")
	fmt.Println()
	fmt.Println("  • The database must be empty for a fresh deployment. Goiabada will")
	fmt.Println("    automatically seed the database with initial data including the")
	fmt.Println("    admin user and OAuth clients configured with the URLs above.")
	fmt.Println()
	fmt.Println("  • For production, consider using a process manager like systemd")
	fmt.Println("    to keep the services running and restart them on failure.")
	fmt.Println()
}

func printComposeInstructions(*Config, string) {
	fmt.Println("To start Goiabada, run:")
	fmt.Println()
	fmt.Printf("    %sdocker compose up -d%s\n", colorCyan, colorReset)
	fmt.Println()
	fmt.Println("Then access:")
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
