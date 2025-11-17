# Getting started

## Overview of Goiabada architecture

Goiabada is made up of three main parts:

- The **auth server**, which manages key endpoints for authorization, token exchange, and authentication forms
- The **admin console**, where you can change settings and manage user accounts and profiles
- A **database** that stores all the data

Starting with version 1.2, the admin console now communicates with the auth server through HTTP calls, and only the auth server accesses the database. This new design provides better separation of concerns and improved security.

![Screenshot](img/screenshot4.png)

## Deployment options

Goiabada can be deployed in several ways depending on your needs:

- **[Local testing](#option-1-local-testing-http-only)** - Quick setup for development and testing (HTTP-only, not for production)
- **[Direct HTTPS](#option-2-direct-https-exposure)** - Production deployment without a reverse proxy (Docker)
- **[Behind reverse proxy](#option-3-behind-a-reverse-proxy)** - Production deployment with Nginx/Traefik handling SSL termination (Docker, recommended)
- **[Native binaries](#option-4-native-binaries-without-docker)** - Production deployment using pre-built binaries without Docker

### Distribution options

The easiest and recommended way to use Goiabada is through **Docker containers**, with images available on [Docker Hub](https://hub.docker.com/repository/docker/leodip/goiabada).

You can also find pre-built binaries on the [releases](https://github.com/leodip/goiabada/releases) page if you prefer to run without containers.

---

## Option 1: For a quick local test (HTTP-only)

**⚠️ For development/testing only - NEVER use in production!**

This setup uses HTTP without encryption and is suitable for local testing on your development machine.

### Choose your database

Goiabada supports multiple databases. Choose one:

#### MySQL

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-mysql.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-mysql.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

#### PostgreSQL

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-postgres.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-postgres.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

#### SQL Server (Microsoft SQL Server)

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-mssql.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-mssql.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

#### SQLite

SQLite is suitable for light workloads and single-instance deployments.

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-sqlite.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-sqlite.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

### What happens on first startup

1. **Auth server initializes** - Creates database schema and admin user
2. **Bootstrap credentials generated** - OAuth client credentials and session keys are auto-generated and written to a shared file
3. **Admin console authenticates** - Loads credentials from the bootstrap file and connects to auth server

The auth server and admin console communicate securely using OAuth2. On first startup, the auth server generates credentials automatically and saves them to a bootstrap file that both containers can access. This happens automatically in Docker - see [Bootstrap credentials explained](#bootstrap-credentials-explained) for details.

### Default admin credentials

```text
Email: admin@example.com
Password: changeme
```

**⚠️ Change these after first login!**

### Customize configuration

All docker-compose files include comments explaining each environment variable. You can modify them directly in the file or create a `.env` file. See the [environment variables documentation](environment-variables.md) for details.

---

## Option 2: Direct HTTPS exposure

**✅ Suitable for production**

This setup exposes Goiabada directly to the internet using HTTPS with SSL certificates. Both the auth server and admin console run on different HTTPS ports since they can't both listen on port 443 simultaneously.

### Prerequisites

You will need:

- Two domain names pointing to your server:
    - `auth.example.com` (for auth server)
    - `admin.example.com` (for admin console)

- SSL certificates for both domains:
    - Use [Let's Encrypt](https://letsencrypt.org/) for free SSL certificates
    - Or use certificates from your SSL provider

### Setup steps

#### 1. Obtain SSL certificates

If you don't have certificates, use [Let's Encrypt](https://letsencrypt.org/) with [Certbot](https://certbot.eff.org/instructions).

Follow the [official Certbot instructions](https://certbot.eff.org/instructions) for your specific operating system and web server setup. You'll need to obtain certificates for both domains: `auth.example.com` and `admin.example.com`.

By default, Let's Encrypt certificates are located at:
```
/etc/letsencrypt/live/auth.example.com/fullchain.pem
/etc/letsencrypt/live/auth.example.com/privkey.pem
/etc/letsencrypt/live/admin.example.com/fullchain.pem
/etc/letsencrypt/live/admin.example.com/privkey.pem
```

#### 2. Download and configure

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-direct.yml
   ```

2. Edit `docker-compose-direct.yml` and update:
   - **Domain names**: Replace `demo-authserver.example.com` and `demo-adminconsole.example.com` with your actual domains
   - **Certificate paths**: Update the volume mounts to point to your certificate locations
   - **Ports**: Auth server uses `8443`, admin console uses `9444` (you can change these)
   - **Database password**: Change `MYSQL_ROOT_PASSWORD` and corresponding database connection strings
   - **Admin credentials**: Update `GOIABADA_ADMIN_EMAIL` and `GOIABADA_ADMIN_PASSWORD`

3. Generate session keys:
   ```bash
   # Generate authentication key (64 bytes = 128 hex chars)
   openssl rand -hex 64

   # Generate encryption key (32 bytes = 64 hex chars)
   openssl rand -hex 32
   ```

4. Add the generated session keys to your docker-compose file:
   ```yaml
   - GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=<your-64-byte-key>
   - GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=<your-32-byte-key>
   ```

#### 3. Start the services

```bash
docker compose -f docker-compose-direct.yml up -d
```

#### 4. Configure DNS

Ensure your DNS records point to your server:
```
auth.example.com    A    <your-server-ip>
admin.example.com   A    <your-server-ip>
```

#### 5. Configure firewall

Open the HTTPS ports (do NOT open HTTP ports to the internet):
```bash
# Auth server HTTPS port
sudo ufw allow 8443/tcp

# Admin console HTTPS port
sudo ufw allow 9444/tcp
```

#### 6. Access your deployment

- Auth server: `https://auth.example.com:8443`
- Admin console: `https://admin.example.com:9444`

### Important security notes

1. **Do NOT expose HTTP ports** - HTTP ports (9090, 9091) should only be accessible internally for container-to-container communication
2. **Use strong passwords** - Change default admin password immediately
3. **Rotate session keys** - Session keys should be unique per deployment
4. **Certificate renewal** - Let's Encrypt certificates expire every 90 days. Set up auto-renewal:
   ```bash
   sudo certbot renew --dry-run
   ```

### Port configuration

By default:

- Auth server: HTTPS 8443, HTTP 9090 (internal only)
- Admin console: HTTPS 9444, HTTP 9091 (internal only)

You can use different ports by modifying the `LISTEN_PORT_HTTPS` environment variables and port mappings in the docker-compose file.

---

## Option 3: Behind a reverse proxy

**✅ Recommended for production**

Using a reverse proxy (like Nginx or Traefik) is the recommended production deployment method. It provides several advantages:

- Both auth server and admin console can share port 443
- Centralized SSL certificate management
- Better performance with caching and compression
- Easier to add rate limiting, WAF, etc.
- Standard production architecture

### Architecture

```
Internet → Nginx (port 443) → {
    auth.example.com    → goiabada-authserver:9090 (HTTP)
    admin.example.com   → goiabada-adminconsole:9091 (HTTP)
}
```

Nginx handles HTTPS termination, Goiabada applications run on HTTP internally.

### Prerequisites

You will need:

- Two domain names pointing to your server:
    - `auth.example.com` (for auth server)
    - `admin.example.com` (for admin console)

- SSL certificates for both domains (see [Direct HTTPS setup](#1-obtain-ssl-certificates) above)

- Nginx installed on your server:
    ```bash
    sudo apt-get update
    sudo apt-get install nginx
    ```

### Setup steps

#### 1. Download and configure Goiabada

1. Download the docker-compose file:
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-reverse-proxy.yml
   ```

2. Edit `docker-compose-reverse-proxy.yml` and update:
   - **Domain names**: Replace example domains with your actual domains in `BASEURL` variables
   - **Database password**: Change `MYSQL_ROOT_PASSWORD`
   - **Admin credentials**: Update `GOIABADA_ADMIN_EMAIL` and `GOIABADA_ADMIN_PASSWORD`
   - **Trust proxy headers**: Ensure these are set to `true`:
     ```yaml
     - GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=true
     - GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=true
     ```
   - **Secure cookies**: Ensure these are set to `true`:
     ```yaml
     - GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=true
     - GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=true
     ```

3. Generate session keys (see [Direct HTTPS setup](#2-download-and-configure) above)

4. Start Goiabada:
   ```bash
   docker compose -f docker-compose-reverse-proxy.yml up -d
   ```

#### 2. Configure Nginx

Create an Nginx configuration file. The path varies by distribution:

```bash
# Debian/Ubuntu
sudo nano /etc/nginx/sites-available/goiabada

# RHEL/CentOS/Fedora
sudo nano /etc/nginx/conf.d/goiabada.conf

# Alpine Linux
sudo nano /etc/nginx/http.d/goiabada.conf
```

Add the following configuration (example, replace domains and certificate paths):

```nginx
# Auth Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    # SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to Goiabada auth server
    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Admin Console
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name admin.example.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

    # SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to Goiabada admin console
    location / {
        proxy_pass http://127.0.0.1:9091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com admin.example.com;

    location / {
        return 301 https://$host$request_uri;
    }
}
```

#### 3. Enable the configuration

**For Debian/Ubuntu** (using sites-available/sites-enabled):

```bash
# Create symbolic link to enable the site
sudo ln -s /etc/nginx/sites-available/goiabada /etc/nginx/sites-enabled/

# Test Nginx configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx
```

**For RHEL/CentOS/Fedora and Alpine** (files in conf.d/ or http.d/ are enabled by default):

```bash
# Test Nginx configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx
```

#### 4. Configure firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Ensure ports 9090 and 9091 are NOT exposed to the internet
# They should only be accessible from localhost
```

#### 5. Access your deployment

- Auth server: `https://auth.example.com`
- Admin console: `https://admin.example.com`

### Using Traefik instead of Nginx

If you prefer Traefik, you can use Docker labels for automatic configuration. See the [Traefik documentation](https://doc.traefik.io/traefik/) for details.

---

## Option 4: Native binaries (without Docker)

**✅ Suitable for production**

If you prefer not to use Docker, you can run Goiabada using pre-built binaries from the [GitHub releases](https://github.com/leodip/goiabada/releases) page. Binaries are available for Linux (amd64/arm64), macOS (Darwin amd64/arm64), and Windows (amd64).

### Prerequisites

You will need:

- A database server (MySQL, PostgreSQL, SQL Server) or SQLite
- SSL certificates (see [Direct HTTPS setup](#1-obtain-ssl-certificates) above)
- A reverse proxy like Nginx (recommended) or direct HTTPS exposure

### Setup steps

#### 1. Download the binaries

Download the appropriate binary package for your platform from the [releases page](https://github.com/leodip/goiabada/releases):

```bash
# Example for Linux amd64
wget https://github.com/leodip/goiabada/releases/download/v1.2.0/goiabada-1.2-linux-amd64.zip
unzip goiabada-1.2-linux-amd64.zip
cd goiabada-1.2-linux-amd64
```

The package contains two binaries:

- `goiabada-authserver` - The authentication server
- `goiabada-adminconsole` - The admin console

#### 2. Set up the database

Set up your database server (MySQL, PostgreSQL, SQL Server, or SQLite). The auth server will automatically create the necessary tables on first startup.

#### 3. Configure environment variables

Create environment files for both services. Create a `.env` file or export environment variables.

**Required variables for auth server:**

```bash
# Admin user (created on first startup)
export GOIABADA_ADMIN_EMAIL="admin@example.com"
export GOIABADA_ADMIN_PASSWORD="changeme"
export GOIABADA_APPNAME="Goiabada"

# Server URLs
export GOIABADA_AUTHSERVER_BASEURL="https://auth.example.com"
export GOIABADA_AUTHSERVER_INTERNALBASEURL="http://127.0.0.1:9090"

# HTTPS configuration (or use reverse proxy)
export GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS="0.0.0.0"
export GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS="8443"
export GOIABADA_AUTHSERVER_CERTFILE="/path/to/fullchain.pem"
export GOIABADA_AUTHSERVER_KEYFILE="/path/to/privkey.pem"

# Database configuration (MySQL example)
export GOIABADA_DB_TYPE="mysql"
export GOIABADA_DB_USERNAME="goiabada"
export GOIABADA_DB_PASSWORD="your-secure-password"
export GOIABADA_DB_HOST="localhost"
export GOIABADA_DB_PORT="3306"
export GOIABADA_DB_NAME="goiabada"

# Session keys (generate with: openssl rand -hex 64 and openssl rand -hex 32)
export GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY="<your-64-byte-hex-key>"
export GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY="<your-32-byte-hex-key>"

# Admin console URLs
export GOIABADA_ADMINCONSOLE_BASEURL="https://admin.example.com"
export GOIABADA_ADMINCONSOLE_INTERNALBASEURL="http://127.0.0.1:9091"

# Bootstrap file location (REQUIRED - where OAuth credentials will be written)
# Without this, you won't be able to get the admin console credentials!
export GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE="/var/lib/goiabada/adminconsole.env"
```

**Required variables for admin console:**

```bash
# Server URLs
export GOIABADA_ADMINCONSOLE_BASEURL="https://admin.example.com"
export GOIABADA_ADMINCONSOLE_INTERNALBASEURL="http://127.0.0.1:9091"

# HTTPS configuration (or use reverse proxy)
export GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS="0.0.0.0"
export GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS="9444"
export GOIABADA_ADMINCONSOLE_CERTFILE="/path/to/fullchain.pem"
export GOIABADA_ADMINCONSOLE_KEYFILE="/path/to/privkey.pem"

# Database configuration (admin console needs read-only access for migrations check)
export GOIABADA_DB_TYPE="mysql"
export GOIABADA_DB_USERNAME="goiabada"
export GOIABADA_DB_PASSWORD="your-secure-password"
export GOIABADA_DB_HOST="localhost"
export GOIABADA_DB_PORT="3306"
export GOIABADA_DB_NAME="goiabada"

# Auth server URLs
export GOIABADA_AUTHSERVER_BASEURL="https://auth.example.com"
export GOIABADA_AUTHSERVER_INTERNALBASEURL="http://127.0.0.1:9090"

# OAuth credentials (you need to manually add these after auth server first startup)
# The auth server will generate these and write them to the bootstrap file
# You need to copy them from /var/lib/goiabada/adminconsole.env after first run
# export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID="admin-console-client"
# export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="<generated-by-auth-server>"
```

**Important - First startup workflow:**

1. Start the **auth server** first with `GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE` configured
2. The auth server will generate OAuth credentials and write them to the bootstrap file (e.g., `/var/lib/goiabada/adminconsole.env`)
3. Open the bootstrap file and copy the values:
   - `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID`
   - `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET`
   - Session keys (if you didn't generate them manually)
4. Add these values to your admin console environment configuration
5. Start the **admin console**

**Note:** The OAuth credentials are NOT logged to the console for security reasons. You must configure the bootstrap file path, otherwise you won't be able to retrieve the credentials.

#### 4. Create systemd services (Linux)

For production deployments on Linux, create systemd service files to manage the processes.

Create `/etc/systemd/system/goiabada-authserver.service`: (example)

```ini
[Unit]
Description=Goiabada authserver
After=network.target mysql.service

[Service]
Type=simple
User=goiabada
Group=goiabada
WorkingDirectory=/opt/goiabada
EnvironmentFile=/etc/goiabada/authserver.env
ExecStart=/opt/goiabada/goiabada-authserver
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/goiabada-adminconsole.service`: (example)

```ini
[Unit]
Description=Goiabada adminconsole
After=network.target goiabada-authserver.service
Requires=goiabada-authserver.service

[Service]
Type=simple
User=goiabada
Group=goiabada
WorkingDirectory=/opt/goiabada
EnvironmentFile=/etc/goiabada/adminconsole.env
ExecStart=/opt/goiabada/goiabada-adminconsole
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Create a dedicated user and directories:

```bash
# Create user
sudo useradd -r -s /bin/false goiabada

# Create directories
sudo mkdir -p /opt/goiabada
sudo mkdir -p /etc/goiabada
sudo mkdir -p /var/lib/goiabada

# Move binaries
sudo mv goiabada-authserver goiabada-adminconsole /opt/goiabada/
sudo chmod +x /opt/goiabada/goiabada-*

# Set ownership
sudo chown -R goiabada:goiabada /opt/goiabada
sudo chown -R goiabada:goiabada /var/lib/goiabada

# Create environment files
sudo nano /etc/goiabada/authserver.env
sudo nano /etc/goiabada/adminconsole.env
```

Enable and start the services:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable goiabada-authserver
sudo systemctl enable goiabada-adminconsole

# Start services
sudo systemctl start goiabada-authserver
sudo systemctl start goiabada-adminconsole

# Check status
sudo systemctl status goiabada-authserver
sudo systemctl status goiabada-adminconsole
```

View logs:

```bash
# Auth server logs
sudo journalctl -u goiabada-authserver -f

# Admin console logs
sudo journalctl -u goiabada-adminconsole -f
```

#### 5. Configure reverse proxy (recommended)

For production, it's recommended to use Nginx as a reverse proxy (see [Option 3](#option-3-behind-a-reverse-proxy) for Nginx configuration). Configure Nginx to proxy to:

- Auth server: `http://127.0.0.1:9090` (or use HTTPS port if configured)
- Admin console: `http://127.0.0.1:9091` (or use HTTPS port if configured)

#### 6. Access your deployment

Once everything is running:

- Auth server: `https://auth.example.com`
- Admin console: `https://admin.example.com`

### Alternative: Running without systemd

If you're not using systemd (e.g., on macOS or Windows), you can run the binaries directly:

```bash
# Start auth server (in one terminal)
./goiabada-authserver

# Start admin console (in another terminal)
./goiabada-adminconsole
```

For production use, consider using a process manager like:

- **Linux**: systemd (recommended), supervisor, or pm2
- **macOS**: launchd or pm2
- **Windows**: NSSM (Non-Sucking Service Manager) or Windows Services

### Static files and templates

The binaries include embedded static files and templates. If you need to customize them:

- Extract static files and templates from the source repository
- Set `GOIABADA_AUTHSERVER_STATICDIR` and `GOIABADA_AUTHSERVER_TEMPLATEDIR` environment variables
- Set `GOIABADA_ADMINCONSOLE_STATICDIR` and `GOIABADA_ADMINCONSOLE_TEMPLATEDIR` environment variables

---

## First login

Once your deployment is running, access the admin console at the configured URL.

Default admin credentials (unless you changed them):

```text
Email: admin@example.com
Password: changeme
```

**⚠️ IMPORTANT:** Change the default password after first login!

---

## Bootstrap credentials explained

Starting with v1.2, Goiabada uses a bootstrap file to share credentials between the auth server and admin console:

1. **Auth server generates** - On first startup, creates OAuth client credentials and session keys
2. **Written to file** - Credentials saved to `/bootstrap/adminconsole.env` (inside container)
3. **Admin console loads** - Reads credentials from the same file via Docker volume mount

### Bootstrap file location

The bootstrap file is shared between containers using a volume mount:

```yaml
volumes:
  - ./bootstrap:/bootstrap  # Creates ./bootstrap directory on your host
```

The file `./bootstrap/adminconsole.env` contains:
```bash
GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=admin-console-client
GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=<generated-secret>
GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=<generated-key>
GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=<generated-key>
GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=<generated-key>
GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=<generated-key>
```

### Manual credential configuration

If you prefer not to use the bootstrap file (for example, in production), you can manually set these environment variables in your docker-compose file or secrets management system.

---

## Configuration

All deployment options use environment variables for configuration. See the [environment variables documentation](environment-variables.md) for a complete reference.

---

## Production checklist

Before deploying to production:

- [ ] Use HTTPS (either direct or behind reverse proxy)
- [ ] Use a production-grade database (MySQL or PostgreSQL recommended)
- [ ] Generate unique session keys (never use defaults)
- [ ] Change default admin password immediately after first login
- [ ] Set strong database password
- [ ] Configure `TRUST_PROXY_HEADERS` correctly (true if behind proxy, false otherwise)
- [ ] Set `SET_COOKIE_SECURE=true` for HTTPS deployments
- [ ] Enable firewall (only expose necessary ports: 443, or 8443/9444 for direct HTTPS)
- [ ] Do NOT expose HTTP ports (9090, 9091) to the internet
- [ ] Set up database backups (automated, tested restores)
- [ ] Configure SSL certificate auto-renewal (Let's Encrypt: `certbot renew`)
- [ ] Set up monitoring and logging
- [ ] Test failover and recovery procedures
- [ ] Review all environment variables in [documentation](environment-variables.md)
- [ ] Document your deployment for your team

---

## Next steps

Now that Goiabada is running, here's what to do next:

- **[Environment Variables Reference](environment-variables.md)** - Complete guide to all configuration options
- **[Main Documentation](https://goiabada.dev)** - Learn about OAuth2/OIDC integration, user management, and permissions
- **[GitHub Repository](https://github.com/leodip/goiabada)** - Source code, issues, and contributions
- **[Docker Hub](https://hub.docker.com/r/leodip/goiabada)** - Official container images

### Quick tasks after deployment:

1. **Change the default admin password** in the admin console
2. **Create your first OAuth client** for your application
3. **Set up your first user** or configure external identity providers
4. **Test the OAuth flow** with your application
5. **Review security settings** and enable 2FA if needed
