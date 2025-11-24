---
title: Setup wizard
description: Use the goiabada-setup wizard to generate ready-to-use configuration files.
---

The **goiabada-setup** wizard is the easiest way to get Goiabada running. It generates configuration files with all credentials pre-configured.

## Download

Download the binary for your platform from the [releases page](https://github.com/leodip/goiabada/releases):

| Platform | Binary |
|----------|--------|
| Linux (x64) | `goiabada-setup-linux-amd64` |
| Linux (ARM) | `goiabada-setup-linux-arm64` |
| macOS (Intel) | `goiabada-setup-darwin-amd64` |
| macOS (Apple Silicon) | `goiabada-setup-darwin-arm64` |
| Windows | `goiabada-setup-windows-amd64.exe` |

## Run the wizard

```bash
# Linux/macOS
chmod +x goiabada-setup-linux-amd64
./goiabada-setup-linux-amd64

# Windows
goiabada-setup-windows-amd64.exe
```

The wizard will ask you a few questions:

1. **Deployment type**:
   - Local testing (HTTP) - for development
   - Production with reverse proxy - for Docker with Nginx/Cloudflare
   - Kubernetes cluster - generates Kubernetes manifests
   - Native binaries - generates environment file for running without Docker

2. **Database** - MySQL, PostgreSQL, SQL Server, or SQLite

3. **Domain names** - Your auth and admin console URLs (production/Kubernetes)

4. **Admin credentials** - Email and password for the first admin user

5. **Database password** - A strong password (auto-generated if you press Enter)

## What gets generated

### For Docker deployments (options 1 and 2)

The wizard creates a `docker-compose.yml` file with:

- All session keys cryptographically generated
- OAuth client credentials pre-configured
- Database service configured
- Both auth server and admin console ready to start

Start with:

```bash
docker compose up -d
```

### For Kubernetes (option 3)

The wizard creates a `goiabada-k8s.yaml` file with:

- Namespace
- Secret (credentials pre-generated and base64 encoded)
- ConfigMap
- Deployments (auth server and admin console)
- Services
- Ingress (with TLS configuration)

Deploy with:

```bash
kubectl apply -f goiabada-k8s.yaml
```

### For native binaries (option 4)

The wizard creates a `goiabada.env` file with:

- All environment variables for both auth server and admin console
- Session keys cryptographically generated
- OAuth client credentials pre-configured
- Database connection settings

Use with:

```bash
source goiabada.env && ./goiabada-authserver
source goiabada.env && ./goiabada-adminconsole
```

## Next steps

- [Quick local test](/getting-started/quick-local-test/) - Test Goiabada locally
- [First login](/getting-started/first-login/) - What to do after starting Goiabada
- [Production deployment](/production-deployment/) - Deploy to production
- [Kubernetes](/production-deployment/kubernetes/) - Kubernetes-specific guide
