# Environment variables

<style>
.md-typeset__table {
    display: block !important;
}
.md-typeset table:not([class]) td {
    border-top: none;
}
</style>

Goiabada consists of two separate applications:

- **Auth server** (`goiabada-authserver`) - Handles authentication, OAuth2/OIDC endpoints, and database access
- **Admin console** (`goiabada-adminconsole`) - Provides the administrative interface

Each application has its own set of environment variables and runs as a separate container/process.

## Configuration format

Goiabada can be configured using **environment variables** or **command-line flags**.

When both an environment variable and a flag are set for the same option, the flag takes precedence.

---

## Auth server vars

These environment variables are **only used by the auth server** (`goiabada-authserver`).

Since version 1.2, only the auth server accesses the database directly. The admin console communicates with the auth server via HTTP APIs.

### Initial setup

**Used by:** Auth server only

These settings are only used when the auth server starts for the first time.

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMIN_EMAIL</code></strong></td><td>Flag: <code>--admin-email</code></td></tr>
<tr><td colspan="2">Email address for the initial admin user. Default: <code>admin@example.com</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMIN_PASSWORD</code></strong></td><td>Flag: <code>--admin-password</code></td></tr>
<tr><td colspan="2">Password for the initial admin user. Default: <code>changeme</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_APPNAME</code></strong></td><td>Flag: <code>--appname</code></td></tr>
<tr><td colspan="2">Application name shown in the UI (can be changed later in the admin console). Default: <code>Goiabada</code></td></tr>
</table>

---

### Database configuration

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_TYPE</code></strong></td><td>Flag: <code>--db-type</code></td></tr>
<tr><td colspan="2">Database type. Supported options:
<ul>
<li><code>mysql</code> - MySQL or MariaDB</li>
<li><code>postgres</code> - PostgreSQL</li>
<li><code>mssql</code> - Microsoft SQL Server</li>
<li><code>sqlite</code> - SQLite (suitable for light workloads and single-instance deployments)</li>
</ul>
Default: <code>sqlite</code></td></tr>
</table>

#### For MySQL, PostgreSQL, and SQL Server

The following variables are used to configure connections to MySQL, MariaDB, PostgreSQL, and Microsoft SQL Server databases. **These variables are NOT used when `GOIABADA_DB_TYPE=sqlite`.**

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_USERNAME</code></strong></td><td>Flag: <code>--db-username</code></td></tr>
<tr><td colspan="2">Database username for authentication. Default: <code>root</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_PASSWORD</code></strong></td><td>Flag: <code>--db-password</code></td></tr>
<tr><td colspan="2">Database password for authentication. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_HOST</code></strong></td><td>Flag: <code>--db-host</code></td></tr>
<tr><td colspan="2">Database server hostname or IP address. In Docker/Kubernetes, use the service name (e.g., <code>mysql-server</code>, <code>postgres</code>). Default: <code>localhost</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_PORT</code></strong></td><td>Flag: <code>--db-port</code></td></tr>
<tr><td colspan="2">Database server TCP port. Standard ports: MySQL=3306, PostgreSQL=5432, SQL Server=1433. Default: <code>3306</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_NAME</code></strong></td><td>Flag: <code>--db-name</code></td></tr>
<tr><td colspan="2">Database (schema) name. The database will be automatically created if it doesn't exist. Default: <code>goiabada</code></td></tr>
</table>

#### For SQLite only

The following variable is used **only when `GOIABADA_DB_TYPE=sqlite`**. When using SQLite, the variables above (USERNAME, PASSWORD, HOST, PORT, NAME) are ignored.

<table width="100%">
<tr><td><strong><code>GOIABADA_DB_DSN</code></strong></td><td>Flag: <code>--db-dsn</code></td></tr>
<tr><td colspan="2">Database DSN (Data Source Name) for SQLite. When using a file, include these pragmas for better performance and concurrency:<br /><code>?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL</code>.<br /><br />Example: <code>file:/home/john/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL</code>.<br />Default: <code>file::memory:?cache=shared</code></td></tr>
</table>

---

### Network configuration

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_BASEURL</code></strong></td><td>Flag: <code>--authserver-baseurl</code></td></tr>
<tr><td colspan="2">The publicly accessible URL where users and applications reach the auth server from outside (e.g., from browsers or external services). This URL is used in OAuth redirects, token issuer claims, and OIDC discovery documents. Example: <code>https://auth.example.com</code>. Default: <code>http://localhost:9090</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_INTERNALBASEURL</code></strong></td><td>Flag: <code>--authserver-internalbaseurl</code></td></tr>
<tr><td colspan="2">Optional internal URL for server-to-server communication within the same network (e.g., Docker network, Kubernetes cluster). When set, the admin console uses this URL for OAuth token exchange and JWT validation (JWKS endpoint) instead of the base URL. This is useful when containers communicate using internal DNS names (like <code>http://goiabada-authserver:9090</code>) while external users access via a different URL. If empty, the base URL is used. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS</code></strong></td><td>Flag: <code>--authserver-listen-host-https</code></td></tr>
<tr><td colspan="2">Network interface to bind for HTTPS. Use <code>0.0.0.0</code> to listen on all interfaces (Docker/production), or <code>127.0.0.1</code> for localhost only (development). Default: <code>0.0.0.0</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS</code></strong></td><td>Flag: <code>--authserver-listen-port-https</code></td></tr>
<tr><td colspan="2">TCP port to listen on for HTTPS connections. Set to empty or 0 to disable HTTPS. Default: <code>9443</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP</code></strong></td><td>Flag: <code>--authserver-listen-host-http</code></td></tr>
<tr><td colspan="2">Network interface to bind for HTTP. Use <code>0.0.0.0</code> to listen on all interfaces (Docker/production), or <code>127.0.0.1</code> for localhost only (development). Default: <code>0.0.0.0</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP</code></strong></td><td>Flag: <code>--authserver-listen-port-http</code></td></tr>
<tr><td colspan="2">TCP port to listen on for HTTP connections. Set to empty or 0 to disable HTTP (recommended in production if using HTTPS). Default: <code>9090</code></td></tr>
</table>

---

### Security settings

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_CERTFILE</code></strong></td><td>Flag: <code>--authserver-certfile</code></td></tr>
<tr><td colspan="2">Path to TLS/SSL certificate file (PEM format) for HTTPS. Required if you want the auth server to handle HTTPS directly. If empty, only HTTP is enabled. <strong>Note:</strong> In production, you can either configure TLS here or run behind a reverse proxy (nginx, Traefik, etc.) that handles HTTPS termination. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_KEYFILE</code></strong></td><td>Flag: <code>--authserver-keyfile</code></td></tr>
<tr><td colspan="2">Path to TLS/SSL private key file (PEM format) for HTTPS. Must be provided together with <code>GOIABADA_AUTHSERVER_CERTFILE</code>. If either is empty, HTTPS will not be enabled. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS</code></strong></td><td>Flag: <code>--authserver-trust-proxy-headers</code></td></tr>
<tr><td colspan="2">Trust reverse proxy headers (<code>True-Client-IP</code>, <code>X-Real-IP</code>, or <code>X-Forwarded-For</code>) to get the client's IP address. Set to <code>true</code> if using a reverse proxy. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_SET_COOKIE_SECURE</code></strong></td><td>Flag: <code>--authserver-set-cookie-secure</code></td></tr>
<tr><td colspan="2">Set the secure flag on cookies. Should be <code>true</code> in production when using HTTPS. Only use <code>false</code> for local HTTP testing. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY</code></strong></td><td>No flag</td></tr>
<tr><td colspan="2"><strong>Required in production.</strong> Hex-encoded session authentication key used for HMAC signatures to verify cookie integrity. Must be exactly 64 bytes (128 hex characters). Generate with: <code>openssl rand -hex 64</code>. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY</code></strong></td><td>No flag</td></tr>
<tr><td colspan="2"><strong>Required in production.</strong> Hex-encoded session encryption key used for AES encryption of cookie data. Must be exactly 32 bytes (64 hex characters). Generate with: <code>openssl rand -hex 32</code>. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_RATELIMITER_ENABLED</code></strong></td><td>Flag: <code>--authserver-ratelimiter-enabled</code></td></tr>
<tr><td colspan="2">Enable rate limiting for security-sensitive endpoints to protect against brute force attacks. When enabled, the following endpoints are rate-limited:
<ul>
<li><strong>Password authentication</strong> (<code>/auth/pwd</code>): 10 requests per minute per email</li>
<li><strong>OTP/2FA verification</strong> (<code>/auth/otp</code>): 10 requests per minute per user</li>
<li><strong>Account activation</strong> (<code>/account/activate</code>): 5 requests per 5 minutes per email</li>
<li><strong>Password reset</strong> (<code>/reset-password</code>): 5 requests per 5 minutes per email</li>
<li><strong>Dynamic Client Registration</strong> (<code>/connect/register</code>): 10 requests per minute per IP address</li>
</ul>
<strong>Recommended:</strong> Enable in production environments for security. You may disable this if you have rate limiting at another layer (e.g., Cloudflare, nginx, API gateway), or for development/testing. Default: <code>false</code></td></tr>
</table>

---

### Customization settings

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_STATICDIR</code></strong></td><td>Flag: <code>--authserver-staticdir</code></td></tr>
<tr><td colspan="2">Directory for static files. If empty, uses files embedded in the binary. Useful for customizations via Docker volumes. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_TEMPLATEDIR</code></strong></td><td>Flag: <code>--authserver-templatedir</code></td></tr>
<tr><td colspan="2">Directory for HTML templates. If empty, uses templates embedded in the binary. Useful for customizations via Docker volumes. Default: <em>(empty)</em></td></tr>
</table>

---

### Logging and debugging

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS</code></strong></td><td>Flag: <code>--authserver-log-http-requests</code></td></tr>
<tr><td colspan="2">Log HTTP requests to console. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_LOG_SQL</code></strong></td><td>Flag: <code>--authserver-log-sql</code></td></tr>
<tr><td colspan="2">Log all SQL statements to console. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE</code></strong></td><td>Flag: <code>--authserver-audit-logs-in-console</code></td></tr>
<tr><td colspan="2">Log audit messages to console. Audit logs track security-relevant events like user logins, permission changes, and administrative actions. Default: <code>true</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS</code></strong></td><td>Flag: <code>--authserver-debug-api-requests</code></td></tr>
<tr><td colspan="2">Enable verbose debug logging for API endpoints (<code>/api/v1/admin/*</code> and <code>/api/v1/account/*</code>). When enabled, logs include full request and response bodies with pretty-printed JSON, headers (with sanitized authorization tokens), and timing information. <strong>Warning:</strong> This logs sensitive data and should only be used during development or debugging. Never enable in production environments. Default: <code>false</code></td></tr>
</table>

---

### Bootstrap settings

**Used by:** Auth server only

<table width="100%">
<tr><td><strong><code>GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE</code></strong></td><td>Flag: <code>--authserver-bootstrap-env-outfile</code></td></tr>
<tr><td colspan="2">File path where bootstrap credentials are automatically written during first-time database initialization. This enables Goiabada's two-step bootstrap process for secure credential management.
<br /><br />
<strong>Two-step bootstrap process:</strong>
<br /><br />
<strong>First run (bootstrap phase):</strong>
<ol>
<li>Auth server initializes - Creates database schema and admin user</li>
<li>Bootstrap credentials generated - OAuth client credentials and session keys are auto-generated and written to this file</li>
<li>Auth server exits - Stops with instructions to configure credentials</li>
<li>Admin console fails - Cannot start without credentials (this is expected!)</li>
</ol>
<strong>After configuration:</strong>
<ol start="5">
<li>Copy credentials - View the generated credentials (requires sudo - file is owned by root):
<pre><code>sudo cat ./bootstrap/bootstrap.env</code></pre>
Copy all 6 credentials from the bootstrap file to your deployment configuration:
<ul>
<li>For <strong>auth server</strong>: <code>GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY</code>, <code>GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY</code></li>
<li>For <strong>admin console</strong>: <code>GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID</code>, <code>GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET</code>, <code>GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY</code>, <code>GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY</code></li>
</ul>
</li>
<li>Restart services - Both services start normally with configured credentials</li>
</ol>
<strong>Docker Compose example:</strong>
<pre><code>goiabada-authserver:
  volumes:
    - ./bootstrap:/bootstrap  # Creates ./bootstrap directory on your host
  environment:
    - GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE=/bootstrap/bootstrap.env
    # UNCOMMENT AND FILL IN AFTER FIRST STARTUP:
    # - GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=&lt;copy from ./bootstrap/bootstrap.env&gt;
    # - GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=&lt;copy from ./bootstrap/bootstrap.env&gt;

goiabada-adminconsole:
  # UNCOMMENT AND FILL IN AFTER FIRST STARTUP:
  # - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=&lt;copy from ./bootstrap/bootstrap.env&gt;
  # - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=&lt;copy from ./bootstrap/bootstrap.env&gt;
  # - GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=&lt;copy from ./bootstrap/bootstrap.env&gt;
  # - GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=&lt;copy from ./bootstrap/bootstrap.env&gt;
</code></pre>
<strong>Security:</strong> The file is created with <code>0600</code> permissions (read/write for owner only). Parent directories are automatically created with <code>0700</code> permissions if they don't exist.
<br /><br />
<strong>Note:</strong> This only runs during initial database seeding (when the database is empty). If you restart without wiping the database, the file will not be regenerated. Default: <em>(empty)</em></td></tr>
</table>

---

## Admin console vars

These environment variables are **only used by the admin console** (`goiabada-adminconsole`).

### Network configuration

**Used by:** Admin console only

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_BASEURL</code></strong></td><td>Flag: <code>--adminconsole-baseurl</code></td></tr>
<tr><td colspan="2">The publicly accessible URL where administrators reach the admin console from outside. This URL is used in OAuth redirects when logging into the admin console. Example: <code>https://admin.example.com</code>. Default: <code>http://localhost:9091</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_INTERNALBASEURL</code></strong></td><td>Flag: <code>--adminconsole-internalbaseurl</code></td></tr>
<tr><td colspan="2">Optional internal URL for server-to-server communication within the same network. Similar to the auth server's internal base URL, this allows services to communicate with the admin console using internal DNS names. If empty, the base URL is used. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS</code></strong></td><td>Flag: <code>--adminconsole-listen-host-https</code></td></tr>
<tr><td colspan="2">Network interface to bind for HTTPS. Use <code>0.0.0.0</code> to listen on all interfaces (Docker/production), or <code>127.0.0.1</code> for localhost only (development). Default: <code>0.0.0.0</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS</code></strong></td><td>Flag: <code>--adminconsole-listen-port-https</code></td></tr>
<tr><td colspan="2">TCP port to listen on for HTTPS connections. Set to empty or 0 to disable HTTPS. Default: <code>9444</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP</code></strong></td><td>Flag: <code>--adminconsole-listen-host-http</code></td></tr>
<tr><td colspan="2">Network interface to bind for HTTP. Use <code>0.0.0.0</code> to listen on all interfaces (Docker/production), or <code>127.0.0.1</code> for localhost only (development). Default: <code>0.0.0.0</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP</code></strong></td><td>Flag: <code>--adminconsole-listen-port-http</code></td></tr>
<tr><td colspan="2">TCP port to listen on for HTTP connections. Set to empty or 0 to disable HTTP (recommended in production if using HTTPS). Default: <code>9091</code></td></tr>
</table>

---

### OAuth settings

**Used by:** Admin console only

Starting with version 1.2, the admin console authenticates against the auth server using OAuth2. The admin console acts as a confidential OAuth client.

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID</code></strong></td><td>Flag: <code>--adminconsole-oauth-client-id</code></td></tr>
<tr><td colspan="2">OAuth client ID for the admin console. This client is automatically created during database seeding. If using <code>GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE</code>, this value is auto-generated and written to the bootstrap file. Default: <code>admin-console-client</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET</code></strong></td><td>Flag: <code>--adminconsole-oauth-client-secret</code></td></tr>
<tr><td colspan="2"><strong>Required.</strong> OAuth client secret for confidential client authentication. This is auto-generated during database seeding. If using <code>GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE</code>, load this from the bootstrap file via <code>env_file</code> in Docker Compose or <code>envFrom</code> in Kubernetes. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_ISSUER</code></strong></td><td>Flag: <code>--adminconsole-issuer</code></td></tr>
<tr><td colspan="2">Expected JWT <code>iss</code> claim for token validation. Must match the auth server's issuer URL. If not specified, defaults to the auth server base URL. Only change this if you've customized the auth server's issuer configuration. Default: <em>(auth server base URL)</em></td></tr>
</table>

---

### Security settings

**Used by:** Admin console only

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_CERTFILE</code></strong></td><td>Flag: <code>--adminconsole-certfile</code></td></tr>
<tr><td colspan="2">Path to TLS/SSL certificate file (PEM format) for HTTPS. Required if you want the admin console to handle HTTPS directly. If empty, only HTTP is enabled. <strong>Note:</strong> In production, you can either configure TLS here or run behind a reverse proxy (nginx, Traefik, etc.) that handles HTTPS termination. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_KEYFILE</code></strong></td><td>Flag: <code>--adminconsole-keyfile</code></td></tr>
<tr><td colspan="2">Path to TLS/SSL private key file (PEM format) for HTTPS. Must be provided together with <code>GOIABADA_ADMINCONSOLE_CERTFILE</code>. If either is empty, HTTPS will not be enabled. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS</code></strong></td><td>Flag: <code>--adminconsole-trust-proxy-headers</code></td></tr>
<tr><td colspan="2">Trust reverse proxy headers (<code>True-Client-IP</code>, <code>X-Real-IP</code>, or <code>X-Forwarded-For</code>) to get the client's IP address. Set to <code>true</code> if using a reverse proxy. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE</code></strong></td><td>Flag: <code>--adminconsole-set-cookie-secure</code></td></tr>
<tr><td colspan="2">Set the secure flag on cookies. Should be <code>true</code> in production when using HTTPS. Only use <code>false</code> for local HTTP testing. Default: <code>false</code></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY</code></strong></td><td>No flag</td></tr>
<tr><td colspan="2"><strong>Required in production.</strong> Hex-encoded session authentication key used for HMAC signatures to verify cookie integrity. Must be exactly 64 bytes (128 hex characters). Generate with: <code>openssl rand -hex 64</code>. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY</code></strong></td><td>No flag</td></tr>
<tr><td colspan="2"><strong>Required in production.</strong> Hex-encoded session encryption key used for AES encryption of cookie data. Must be exactly 32 bytes (64 hex characters). Generate with: <code>openssl rand -hex 32</code>. Default: <em>(empty)</em></td></tr>
</table>

---

### Customization settings

**Used by:** Admin console only

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_STATICDIR</code></strong></td><td>Flag: <code>--adminconsole-staticdir</code></td></tr>
<tr><td colspan="2">Directory for static files. If empty, uses files embedded in the binary. Useful for customizations via Docker volumes. Default: <em>(empty)</em></td></tr>
</table>

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_TEMPLATEDIR</code></strong></td><td>Flag: <code>--adminconsole-templatedir</code></td></tr>
<tr><td colspan="2">Directory for HTML templates. If empty, uses templates embedded in the binary. Useful for customizations via Docker volumes. Default: <em>(empty)</em></td></tr>
</table>

---

### Logging and debugging

**Used by:** Admin console only

<table width="100%">
<tr><td><strong><code>GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS</code></strong></td><td>Flag: <code>--adminconsole-log-http-requests</code></td></tr>
<tr><td colspan="2">Log HTTP requests to console. Default: <code>false</code></td></tr>
</table>

---

## Important notes

### Session keys

Both the auth server and admin console require session authentication and encryption keys in production. These are cryptographic keys used to secure session cookies.

**Why hex-encoded?** These keys must be high-entropy binary data (random bytes) for cryptographic security. Hex encoding is used to safely represent these binary keys as strings in environment variables.

**Required format:**
- **Authentication key**: 64 bytes = 128 hex characters (used for HMAC signatures)
- **Encryption key**: 32 bytes = 64 hex characters (used for AES encryption)

**Generation:**

Use OpenSSL to generate cryptographically secure random keys:

```bash
# Generate authentication key (64 bytes)
openssl rand -hex 64

# Generate encryption key (32 bytes)
openssl rand -hex 32
```

**Important:** Do not use regular passwords or plain text strings. The keys must be randomly generated hex-encoded values for proper security.

### Database access in v1.2

Starting with version 1.2, **only the auth server accesses the database directly**. The admin console communicates with the auth server through HTTP API calls using OAuth2 authentication.

This means:

- Database environment variables (`GOIABADA_DB_*`) are only used by the auth server
- The admin console no longer needs database configuration
- The admin console authenticates as an OAuth client to access auth server APIs

