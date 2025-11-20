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

- **[Local testing](#option-1-for-a-quick-local-test-http-only)** - Quick setup for development and testing (HTTP-only, not for production)
- **[With Cloudflare](#option-2-with-cloudflare-proxy)** - Production deployment with Cloudflare handling SSL (recommended for Cloudflare users)
- **[Reverse proxy without Cloudflare](#option-3-reverse-proxy-without-cloudflare)** - Production deployment with Nginx/Traefik handling SSL termination (recommended without Cloudflare)
- **[Kubernetes cluster](#option-4-kubernetes-cluster-deployment)** - Production deployment on Kubernetes with ingress controller
- **[Native binaries](#option-5-native-binaries-without-docker)** - Production deployment using pre-built binaries without Docker

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

1. Download the docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-mysql.yml)):
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-mysql.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-mysql.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

#### PostgreSQL

1. Download the docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-postgres.yml)):
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-postgres.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-postgres.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

#### SQL Server (Microsoft SQL Server)

1. Download the docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-mssql.yml)):
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

1. Download the docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-sqlite.yml)):
   ```bash
   curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-sqlite.yml
   ```

2. Start the services:
   ```bash
   docker compose -f docker-compose-sqlite.yml up -d
   ```

3. Access the admin console at: http://localhost:9091

### What happens on first startup

Goiabada uses a **two-step bootstrap process**:

**First run (`docker compose up`):**

1. **Auth server initializes** - Creates database schema and admin user
2. **Bootstrap credentials generated** - OAuth client credentials and session keys are auto-generated and written to `./bootstrap/bootstrap.env`
3. **Auth server exits** - Stops with instructions to configure credentials
4. **Admin console fails** - Cannot start without credentials (this is expected!)

**After configuration:**

5. **Copy credentials** - Open the bootstrap file and manually copy all 6 credentials to your `docker-compose.yml`:

   ```bash
   # View the generated credentials (requires sudo - file is owned by root)
   sudo cat ./bootstrap/bootstrap.env
   ```

   Copy the values from the bootstrap file and paste them into your docker-compose file by uncommenting and filling in these lines:

   - For **goiabada-authserver** service (2 session keys):
     - `GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY`
     - `GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY`

   - For **goiabada-adminconsole** service (2 OAuth credentials + 2 session keys):
     - `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID`
     - `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET`
     - `GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY`
     - `GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY`

   Edit your docker-compose file and paste the credential values:

   ```bash
   # Edit the file with your preferred editor
   nano docker-compose-mysql.yml
   # or
   vim docker-compose-mysql.yml
   ```

   Find the commented credential lines in both service sections and uncomment them, then paste the corresponding values from the bootstrap file.

6. **Run `docker compose up` again** - both services start normally with configured credentials:

   ```bash
   docker compose -f docker-compose-mysql.yml up -d
   ```

This two-step process ensures explicit credential management and works across all deployment platforms (Docker, Kubernetes, bare metal). See [bootstrap settings](environment-variables.md#bootstrap-settings) for detailed instructions.

### Default admin credentials

```text
Email: admin@example.com
Password: changeme
```

**⚠️ Change these after first login!**

### Customize configuration

All docker-compose files include comments explaining each environment variable. You can modify them directly in the file or create a `.env` file. See the [environment variables documentation](environment-variables.md) for details.

---

## Option 2: With Cloudflare proxy

**✅ Recommended for production with Cloudflare**

When using Cloudflare with the proxy enabled (orange cloud icon), Cloudflare handles SSL termination at the edge. This is one of the simplest and most common production setups.

You have two setup options depending on your server configuration:

- **Simple setup** - Cloudflare connects directly to Goiabada (no reverse proxy on your server)
- **With existing Nginx/reverse proxy** - Cloudflare connects to Nginx, which proxies to Goiabada

Both options work the same way from Cloudflare's perspective. Choose based on whether you already have Nginx running other sites on your server.

---

### Setup A: Using Cloudflare Tunnel (No Nginx required)

**Use this if:** You want the simplest setup without managing SSL certificates or configuring Nginx/reverse proxy.

**What is Cloudflare Tunnel?**

Cloudflare Tunnel creates a secure, outbound-only connection from your server to Cloudflare's network. It eliminates the need for:

- Opening inbound firewall ports
- Managing SSL/TLS certificates
- Setting up a reverse proxy (Nginx/Traefik)
- Exposing your server's IP address publicly

**Pricing:** ✅ Free on Cloudflare's free plan (up to 50 tunnels with unlimited bandwidth)

#### Prerequisites

You will need:

- A Cloudflare account (free tier works 🙂)
- Your domain (`example.com`) added to Cloudflare
- Two subdomains you want to use:
    - `auth.example.com` (for auth server)
    - `admin.example.com` (for admin console)
- Docker and docker-compose installed on your server

#### Architecture

```
User
  ↓ HTTPS
Cloudflare
  ↓ Cloudflare Tunnel (encrypted)
Your Server (localhost:9090 or :9091)
```

No public IP exposure, no open firewall ports needed!

#### Setup steps

**1. Start Goiabada containers**

Download the reverse-proxy docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-reverse-proxy.yml)):

```bash
curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-reverse-proxy.yml
```

Edit the file and update:

- Domain names in `BASEURL` variables
- Database password
- Admin credentials
- Ensure `TRUST_PROXY_HEADERS=true` (important for Cloudflare Tunnel)
- Ensure `SET_COOKIE_SECURE=true` (for HTTPS)

Bootstrap and start containers:

```bash
# First run - generates credentials
docker compose -f docker-compose-reverse-proxy.yml up

# View generated credentials
sudo cat ./bootstrap/bootstrap.env

# Copy all 6 credentials to your docker-compose file, then restart
docker compose -f docker-compose-reverse-proxy.yml up -d
```

See detailed bootstrap instructions in the [environment variables documentation](environment-variables.md#bootstrap-settings).

Verify containers are running:

```bash
# Check containers are up
docker ps | grep goiabada
echo

# Test auth server health endpoint (should return "healthy")
curl http://localhost:9090/health
echo

# Test admin console health endpoint (should return "healthy")
curl http://localhost:9091/health
echo
```

Expected output for health checks: `healthy`

**2. Create a Cloudflare Tunnel**

Log in to the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/):

1. Go to **Networks** → **Connectors**
2. Click **Create a tunnel**
3. Select **Cloudflared** as the connector type
4. Click **Next**
5. Enter a tunnel name (e.g., `goiabada-tunnel`)
6. Click **Save tunnel**

**3. Install cloudflared on your server**

The Cloudflare dashboard will show installation commands for your operating system. Follow the commands and complete the installation.

Verify it's running:

```bash
sudo systemctl status cloudflared
```

Return to the Cloudflare dashboard (Networks → Connectors) and you should see your connector listed as **HEALTHY**.

**4. Configure public hostnames**

In the Cloudflare Zero Trust dashboard, on your tunnel's configuration page (accessed via the three-dots menu):

1. Click the **Published application routes** tab
2. Add a new published application route

**For the auth server:**

**Hostname section:**

- **Subdomain**: `auth`
- **Domain**: Select `example.com` from the dropdown
- **Path**: Leave blank

**Service section:**

- **Type**: Select `HTTP` from the dropdown
- **URL**: `localhost:9090`

Click **Save**

**Note**: If you get an error "An A, AAAA, or CNAME record with that host already exists", go to Cloudflare Dashboard → DNS → Records, delete the existing DNS record for `auth.example.com`, then try again.

**For the admin console:**

Add another route by filling out the form again:

**Hostname section:**

- **Subdomain**: `admin`
- **Domain**: Select `example.com` from the dropdown
- **Path**: Leave blank

**Service section:**

- **Type**: Select `HTTP` from the dropdown
- **URL**: `localhost:9091`

Click **Save**

**Note**: If you get the DNS conflict error again, delete the existing record for `admin.example.com` in Cloudflare DNS, then try again.

**5. Configure SSL/TLS settings**

Go to your domain in the main Cloudflare dashboard:

1. **SSL/TLS** → **Overview**
   - Set encryption mode to **Full** (not "Full strict" - we're using HTTP to localhost)

2. **SSL/TLS** → **Edge Certificates**
   - Enable **"Always Use HTTPS"** toggle

**6. Verify DNS records**

Cloudflare automatically creates DNS records for your tunnel hostnames. Verify:

1. Go to **DNS** → **Records**
2. You should see CNAME records for both `auth` and `admin` pointing to your tunnel
3. These records should be **Proxied** (orange cloud)

#### Access your deployment

- Auth server: `https://auth.example.com`
- Admin console: `https://admin.example.com`

No port numbers needed - Cloudflare handles everything!

Also, No inbound firewall ports need to be opened! Cloudflare Tunnel uses outbound connections only.

---

### Setup B: With existing Nginx (Cloudflare → Nginx → Goiabada)

**Use this if:** You already have Nginx (or another reverse proxy) running on your server, typically because you're hosting multiple sites/applications.

In this setup:

- Cloudflare provides the first layer of SSL/TLS termination
- Nginx receives HTTPS from Cloudflare (with valid SSL certificates) and proxies to Goiabada's HTTP ports
- Ports 9090 and 9091 are NOT exposed to the internet (only Nginx on localhost accesses them)
- End-to-end encryption: User → Cloudflare (HTTPS) → Nginx (HTTPS) → Goiabada (HTTP on localhost)

#### Cloudflare SSL configuration

Same as Setup A - configure SSL settings in your Cloudflare dashboard:

**SSL/TLS encryption mode:**

- Go to **SSL/TLS** → **Overview**
- Set encryption mode to **Full (strict)** (recommended for production)

**Always Use HTTPS:**

- Go to **SSL/TLS** → **Edge Certificates**
- Scroll down and enable the **"Always Use HTTPS"** toggle

#### Setup steps

**1. Use the reverse proxy docker-compose file**

Download the file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-reverse-proxy.yml)):

```bash
curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-reverse-proxy.yml
```

**2. Configure Goiabada**

Edit `docker-compose-reverse-proxy.yml`:

- Update domain names to your actual domains
- Change database password
- Update admin credentials
- Ensure these are set:

```yaml
- GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=true
- GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=true
- GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=true
- GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=true
```

**3. Bootstrap credentials**

Follow the two-step bootstrap process:

```bash
docker compose -f docker-compose-reverse-proxy.yml up
# Wait for auth server to exit, then:
sudo cat ./bootstrap/bootstrap.env
# Copy credentials to docker-compose file and restart:
docker compose -f docker-compose-reverse-proxy.yml up -d
```

See detailed bootstrap instructions in the [environment variables documentation](environment-variables.md#bootstrap-settings).

Verify containers are running:

```bash
# Check containers are up
docker ps | grep goiabada
echo

# Test auth server health endpoint (should return "healthy")
curl http://localhost:9090/health
echo

# Test admin console health endpoint (should return "healthy")
curl http://localhost:9091/health
echo
```

Expected output for health checks: `healthy`

**4. Get SSL certificates**

Obtain Let's Encrypt certificates for your domains:

```bash
# Install certbot if not already installed
sudo apt-get update
sudo apt-get install certbot

# Create webroot directory for ACME challenges
sudo mkdir -p /var/www/certbot
```

Create a temporary HTTP-only Nginx configuration file for certificate acquisition:

```bash
# Create new Nginx config file (Ubuntu/Debian)
sudo nano /etc/nginx/sites-available/goiabada
```

Add this temporary configuration to allow certbot verification:

```nginx
# Temporary config for certificate acquisition
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name admin.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://127.0.0.1:9091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration and reload Nginx:

```bash
# Enable the site (Ubuntu/Debian)
sudo ln -s /etc/nginx/sites-available/goiabada /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo nginx -s reload
```

**Important**: Before running certbot, temporarily disable Cloudflare proxy:

- Go to Cloudflare DNS settings
- Click the orange cloud next to `auth.example.com` to make it gray (DNS only)
- Click the orange cloud next to `admin.example.com` to make it gray (DNS only)
- Wait 1-2 minutes for DNS propagation

Now get the certificates:

```bash
# Get certificate for auth server
sudo certbot certonly --webroot -w /var/www/certbot -d auth.example.com

# Get certificate for admin console
sudo certbot certonly --webroot -w /var/www/certbot -d admin.example.com
```

After certificates are obtained, **re-enable Cloudflare proxy** (turn clouds back to orange).

**5. Configure Nginx with HTTPS**

Edit the Nginx configuration file to replace the temporary config with production HTTPS configuration:

```bash
# Edit the same config file
sudo nano /etc/nginx/sites-available/goiabada
```

Replace the entire contents with this production HTTPS configuration:

```nginx
# Auth Server - HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    # SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Buffer settings for large headers (required for auth flows)
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}

# Auth Server - HTTP redirect
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# Admin Console - HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name admin.example.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

    # SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:9091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Buffer settings for large headers (required for auth flows)
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}

# Admin Console - HTTP redirect
server {
    listen 80;
    listen [::]:80;
    server_name admin.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}
```

**Important**: This configuration uses HTTPS (port 443) because Cloudflare in Full (strict) mode sends HTTPS to your origin and validates the certificate.

**6. Test and reload Nginx**

```bash
sudo nginx -t
sudo nginx -s reload
```

#### Configure Cloudflare DNS

Ensure both domains point to your server with **proxy enabled** (orange cloud):

```
Type: A       Name: auth     Content: <your-server-ipv4>    Proxy: ON (orange cloud)
Type: A       Name: admin    Content: <your-server-ipv4>    Proxy: ON (orange cloud)
```

**Optional - IPv6 support**: If your server has IPv6 connectivity, also add AAAA records:

```
Type: AAAA    Name: auth     Content: <your-server-ipv6>    Proxy: ON (orange cloud)
Type: AAAA    Name: admin    Content: <your-server-ipv6>    Proxy: ON (orange cloud)
```

Note: The Nginx configuration already includes IPv6 listeners (`listen [::]:443` and `listen [::]:80`), so IPv6 will work automatically if you add AAAA records.

#### Configure firewall

**Do NOT expose ports 9090 and 9091** - they should only be accessible from localhost:

```bash
# Allow HTTP and HTTPS for Nginx
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Ports 9090 and 9091 should NOT be opened to the internet
# They're only accessible via localhost (127.0.0.1)
# Nginx proxies requests to these ports internally
```

#### Access your deployment

- Auth server: `https://auth.example.com`
- Admin console: `https://admin.example.com`

---

## Option 3: Reverse proxy without Cloudflare

**✅ Recommended for production without Cloudflare**

**Use this if:** You want to run Goiabada without Cloudflare, using Nginx or Traefik for SSL termination.

Using a reverse proxy is a standard production deployment method that provides several advantages:

- Both auth server and admin console share port 443 (standard HTTPS)
- Centralized SSL certificate management (Let's Encrypt with Certbot)
- Better performance with caching and compression
- Easier to add rate limiting, WAF, etc.
- Clean URLs without port numbers

### Architecture

```
Internet → Nginx (HTTPS port 443) → {
    auth.example.com    → goiabada-authserver:9090 (HTTP)
    admin.example.com   → goiabada-adminconsole:9091 (HTTP)
}
```

Nginx handles HTTPS termination with SSL certificates. Goiabada applications run on HTTP internally (ports 9090 and 9091 are NOT exposed to the internet).

### Prerequisites

You will need:

- Two domain names pointing to your server:
    - `auth.example.com` (for auth server)
    - `admin.example.com` (for admin console)

- SSL certificates for both domains:
    - Use [Let's Encrypt](https://letsencrypt.org/) for free SSL certificates (see [Option 2 - Setup B](#option-2-setup-b-cloudflare-with-nginx) for detailed certbot instructions)
    - Or use certificates from your SSL provider

- Nginx installed on your server:
    ```bash
    sudo apt-get update
    sudo apt-get install nginx
    ```

### Setup steps

#### 1. Download and configure Goiabada

Download the docker-compose file ([view file](https://github.com/leodip/goiabada/blob/main/src/build/docker-compose-reverse-proxy.yml)):

```bash
curl -O https://raw.githubusercontent.com/leodip/goiabada/main/src/build/docker-compose-reverse-proxy.yml
```

Edit `docker-compose-reverse-proxy.yml` and update the following:

**Domain names**: Replace example domains with your actual domains in `BASEURL` variables

**Database password**: Change `MYSQL_ROOT_PASSWORD`

**Admin credentials**: Update `GOIABADA_ADMIN_EMAIL` and `GOIABADA_ADMIN_PASSWORD`

**Trust proxy headers**: Ensure these are set to `true`:

```yaml
- GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=true
- GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=true
```

**Secure cookies**: Ensure these are set to `true`:

```yaml
- GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=true
- GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=true
```

#### 2. Bootstrap credentials

Goiabada uses a two-step bootstrap process:

```bash
# First run - generates credentials
docker compose -f docker-compose-reverse-proxy.yml up
```

The auth server will seed the database, generate credentials, and exit. View and copy the credentials:

```bash
sudo cat ./bootstrap/bootstrap.env
```

Copy all 6 credentials to your `docker-compose-reverse-proxy.yml` file. See [bootstrap settings](environment-variables.md#bootstrap-settings) for detailed instructions.

```bash
# Second run - normal operation
docker compose -f docker-compose-reverse-proxy.yml up -d
```

#### 3. Configure Nginx

Create an Nginx configuration file. The path varies by distribution:

```bash
# Debian/Ubuntu
sudo nano /etc/nginx/sites-available/goiabada
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

        # Buffer settings for large headers (required for auth flows)
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
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

        # Buffer settings for large headers (required for auth flows)
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
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

#### 4. Enable the configuration

```bash
# Test Nginx configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx
```

#### 5. Configure firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Ensure ports 9090 and 9091 are NOT exposed to the internet
# They should only be accessible from localhost
```

#### 6. Access your deployment

- Auth server: `https://auth.example.com`
- Admin console: `https://admin.example.com`

---

## Option 4: Kubernetes cluster deployment

**✅ Suitable for production**

This section covers the key aspects of deploying Goiabada on Kubernetes, focusing on the bootstrap process which is unique to Goiabada's credential generation workflow.

### Prerequisites

- Kubernetes cluster with kubectl configured
- Ingress controller installed (nginx-ingress, traefik, etc.)
- cert-manager for automatic SSL certificates (or manual certs)
- Database (managed service like AWS RDS, GCP Cloud SQL, or in-cluster)
- Two domain names: `auth.example.com` and `admin.example.com`

### Bootstrap workflow for Kubernetes

The challenge with Kubernetes is that Goiabada's bootstrap process requires running the auth server once to generate credentials, then configuring those credentials before normal operation. Here's how to handle this:

#### Step 1: Run bootstrap job

Create a Kubernetes Job that runs the auth server in bootstrap mode:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: goiabada-bootstrap
  namespace: goiabada
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
---
apiVersion: batch/v1
kind: Job
metadata:
  name: goiabada-bootstrap
  namespace: goiabada
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: authserver
        image: leodip/goiabada:authserver-latest
        env:
        # Admin user configuration
        - name: GOIABADA_ADMIN_EMAIL
          value: "admin@example.com"
        - name: GOIABADA_ADMIN_PASSWORD
          value: "changeme"
        - name: GOIABADA_APPNAME
          value: "Goiabada"

        # Server URLs
        - name: GOIABADA_AUTHSERVER_BASEURL
          value: "https://auth.example.com"
        - name: GOIABADA_AUTHSERVER_INTERNALBASEURL
          value: "http://goiabada-authserver:9090"
        - name: GOIABADA_ADMINCONSOLE_BASEURL
          value: "https://admin.example.com"
        - name: GOIABADA_ADMINCONSOLE_INTERNALBASEURL
          value: "http://goiabada-adminconsole:9091"

        # Database configuration (from secret)
        - name: GOIABADA_DB_TYPE
          value: "mysql"
        - name: GOIABADA_DB_HOST
          valueFrom:
            secretKeyRef:
              name: goiabada-database
              key: host
        - name: GOIABADA_DB_PORT
          valueFrom:
            secretKeyRef:
              name: goiabada-database
              key: port
        - name: GOIABADA_DB_NAME
          valueFrom:
            secretKeyRef:
              name: goiabada-database
              key: database
        - name: GOIABADA_DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: goiabada-database
              key: username
        - name: GOIABADA_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: goiabada-database
              key: password

        # Bootstrap file output location
        - name: GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE
          value: "/bootstrap/bootstrap.env"

        volumeMounts:
        - name: bootstrap
          mountPath: /bootstrap

      volumes:
      - name: bootstrap
        persistentVolumeClaim:
          claimName: goiabada-bootstrap
```

Deploy the job:

```bash
kubectl apply -f bootstrap-job.yaml
```

Wait for the job to complete (it will exit after generating credentials):

```bash
kubectl wait --for=condition=complete job/goiabada-bootstrap -n goiabada --timeout=120s
```

#### Step 2: Extract bootstrap credentials

Copy the bootstrap file from the persistent volume:

```bash
# Create a temporary pod to access the PVC
kubectl run -n goiabada bootstrap-reader --image=busybox --restart=Never \
  --overrides='
{
  "spec": {
    "containers": [{
      "name": "bootstrap-reader",
      "image": "busybox",
      "command": ["sleep", "3600"],
      "volumeMounts": [{
        "name": "bootstrap",
        "mountPath": "/bootstrap"
      }]
    }],
    "volumes": [{
      "name": "bootstrap",
      "persistentVolumeClaim": {
        "claimName": "goiabada-bootstrap"
      }
    }]
  }
}'

# Wait for pod to be ready
kubectl wait --for=condition=ready pod/bootstrap-reader -n goiabada --timeout=60s

# Copy the bootstrap file to your local machine
kubectl cp goiabada/bootstrap-reader:/bootstrap/bootstrap.env ./bootstrap.env

# Clean up the reader pod
kubectl delete pod bootstrap-reader -n goiabada
```

#### Step 3: Create Kubernetes secrets from bootstrap file

Open `./bootstrap.env` and create secrets from the values:

```bash
# Extract values from bootstrap file (example commands)
CLIENT_ID=$(grep GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID ./bootstrap.env | cut -d'=' -f2)
CLIENT_SECRET=$(grep GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET ./bootstrap.env | cut -d'=' -f2)
AUTH_SESSION_AUTH_KEY=$(grep GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY ./bootstrap.env | cut -d'=' -f2)
AUTH_SESSION_ENC_KEY=$(grep GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY ./bootstrap.env | cut -d'=' -f2)
ADMIN_SESSION_AUTH_KEY=$(grep GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY ./bootstrap.env | cut -d'=' -f2)
ADMIN_SESSION_ENC_KEY=$(grep GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY ./bootstrap.env | cut -d'=' -f2)

# Create secrets for auth server
kubectl create secret generic goiabada-authserver-session -n goiabada \
  --from-literal=authentication-key="$AUTH_SESSION_AUTH_KEY" \
  --from-literal=encryption-key="$AUTH_SESSION_ENC_KEY"

# Create secrets for admin console
kubectl create secret generic goiabada-adminconsole-credentials -n goiabada \
  --from-literal=oauth-client-id="$CLIENT_ID" \
  --from-literal=oauth-client-secret="$CLIENT_SECRET" \
  --from-literal=session-authentication-key="$ADMIN_SESSION_AUTH_KEY" \
  --from-literal=session-encryption-key="$ADMIN_SESSION_ENC_KEY"
```

**Security note:** Delete the local `./bootstrap.env` file after creating secrets. Store it securely if you need to keep a backup.

#### Step 4: Deploy auth server and admin console

Now deploy both services with the secrets configured. Example deployment snippets:

**Auth server deployment:**
```yaml
env:
- name: GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY
  valueFrom:
    secretKeyRef:
      name: goiabada-authserver-session
      key: authentication-key
- name: GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: goiabada-authserver-session
      key: encryption-key
# ... other env vars from ConfigMap
```

**Admin console deployment:**
```yaml
env:
- name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: goiabada-adminconsole-credentials
      key: oauth-client-id
- name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: goiabada-adminconsole-credentials
      key: oauth-client-secret
- name: GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY
  valueFrom:
    secretKeyRef:
      name: goiabada-adminconsole-credentials
      key: session-authentication-key
- name: GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: goiabada-adminconsole-credentials
      key: session-encryption-key
# ... other env vars from ConfigMap
```

#### Step 5: Clean up bootstrap resources

After successful deployment:

```bash
# Delete the bootstrap job and PVC
kubectl delete job goiabada-bootstrap -n goiabada
kubectl delete pvc goiabada-bootstrap -n goiabada
```

### Standard Kubernetes resources needed

Once bootstrap is complete, you'll need these standard Kubernetes resources:

- **Namespace**: Dedicated namespace (e.g., `goiabada`)
- **Secrets**: Database connection, credentials (created in bootstrap steps above)
- **ConfigMaps**: Non-sensitive configuration (URLs, feature flags, etc.)
- **Deployments**: Auth server and admin console (use `leodip/goiabada:authserver-latest` and `leodip/goiabada:adminconsole-latest`)
- **Services**: ClusterIP services for both deployments (ports 9090 and 9091)
- **Ingress**: TLS ingress with rules for both domains (use cert-manager for automatic SSL)

Example ingress configuration:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: goiabada
  namespace: goiabada
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auth.example.com
    secretName: goiabada-authserver-tls
  - hosts:
    - admin.example.com
    secretName: goiabada-adminconsole-tls
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: goiabada-authserver
            port:
              number: 9090
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: goiabada-adminconsole
            port:
              number: 9091
```

### Production considerations

- **Database**: Use managed database services (AWS RDS, GCP Cloud SQL, Azure Database) instead of running database in-cluster
- **Secrets management**: Consider using external-secrets-operator, sealed-secrets, or cloud-native secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- **High availability**: Run multiple replicas with pod anti-affinity rules
- **Resource limits**: Set appropriate CPU/memory requests and limits
- **Monitoring**: Integrate with Prometheus for metrics
- **Ingress**: Configure similar to [reverse proxy setup](#option-3-reverse-proxy-without-cloudflare) - same concepts apply

### Important environment variables

Ensure these are set correctly in your ConfigMaps/Secrets:

- `GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=true` (behind ingress)
- `GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=true` (using HTTPS)
- `GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=true` (behind ingress)
- `GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=true` (using HTTPS)

See [environment variables documentation](environment-variables.md) for complete reference.

---

## Option 5: Native binaries (without Docker)

**✅ Suitable for production**

If you prefer not to use Docker, you can run Goiabada using pre-built binaries from the [GitHub releases](https://github.com/leodip/goiabada/releases) page. Binaries are available for Linux (amd64/arm64), macOS (Darwin amd64/arm64), and Windows (amd64).

### Prerequisites

You will need:

- A database server (MySQL, PostgreSQL, SQL Server) or SQLite
- SSL certificates if using HTTPS:
    - Use [Let's Encrypt](https://letsencrypt.org/) for free SSL certificates
    - Or use certificates from your SSL provider
- A reverse proxy like Nginx (recommended for production)

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
export GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE="/var/lib/goiabada/bootstrap.env"
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

# Auth server URLs
export GOIABADA_AUTHSERVER_BASEURL="https://auth.example.com"
export GOIABADA_AUTHSERVER_INTERNALBASEURL="http://127.0.0.1:9090"

# OAuth credentials (you need to manually add these after auth server first startup)
# The auth server will generate these and write them to the bootstrap file
# You need to copy them from /var/lib/goiabada/bootstrap.env after first run
# export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID="admin-console-client"
# export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="<generated-by-auth-server>"
```

**Important - Bootstrap Process:**

Goiabada uses a two-step bootstrap process to securely generate and configure credentials. See [bootstrap settings](environment-variables.md#bootstrap-settings) for detailed instructions.

1. **First run** - Start the auth server with `GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE` configured. The auth server will seed the database, generate credentials, write them to the bootstrap file, and exit.

2. **Configure credentials** - View the bootstrap file and copy all 6 credentials to your environment configuration:

   ```bash
   sudo cat /var/lib/goiabada/bootstrap.env
   ```

   Add these to your systemd service files or environment scripts.

3. **Second run** - Start both the auth server and admin console with the configured credentials. Both services will now run normally.

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
EnvironmentFile=/etc/goiabada/bootstrap.env
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
sudo nano /etc/goiabada/bootstrap.env
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

For production, it's recommended to use Nginx as a reverse proxy (see [Option 3](#option-3-reverse-proxy-without-cloudflare) for Nginx configuration). Configure Nginx to proxy to:

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
