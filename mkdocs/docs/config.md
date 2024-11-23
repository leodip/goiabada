# Config

Goiabada uses environment variables and/or executable flags to configure its behavior. 

If both an environment variable and a flag are set, the flag takes precedence.

---

`GOIABADA_AUTHSERVER_BASEURL` and `GOIABADA_ADMINCONSOLE_BASEURL`

Flag: `--authserver-baseurl` and `--adminconsole-baseurl`

Default: http://localhost:9090 (auth server) and http://localhost:9091 (admin console)

Description: The base URL of the application. This is used for external access into the application.

---

`GOIABADA_AUTHSERVER_INTERNALBASEURL` and `GOIABADA_ADMINCONSOLE_INTERNALBASEURL`

Flag: `--authserver-internalbaseurl` and `--adminconsole-internalbaseurl`

Default: (empty string)

Description: The internal base URL of the application. This is used for internal communication (for instance, when the `adminconsole` needs to call the `token` endpoint on the `authserver`)

---

`GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS` and `GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS`

Flag: `--authserver-listen-host-https` and `--adminconsole-listen-host-https`

Default: 0.0.0.0 (all network interfaces)

Description: The host to listen on for HTTPS access.

---

`GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS` and `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS`

Flag: `--authserver-listen-port-https` and `--adminconsole-listen-port-https`

Default: 9443 (auth server) and 9444 (admin console)

Description: The port to listen on for HTTPS access.

---

`GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP` and `GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP`

Flag: `--authserver-listen-host-http` and `--adminconsole-listen-host-http`

Default: 0.0.0.0 (all network interfaces)

Description: The host to listen on for HTTP access.

---

`GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP` and `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP`

Flag: `--authserver-listen-port-http` and `--adminconsole-listen-port-http`

Default: 9090 (auth server) and 9091 (admin console)

Description: The port to listen on for HTTP access.

---

`GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS` and `GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS`

Flag: `--authserver-trust-proxy-headers` and `--adminconsole-trust-proxy-headers`

Default: false

Description: If you're using a reverse proxy, you should trust the headers sent by it. The `True-Client-IP`, `X-Real-IP` or the `X-Forwarded-For` header will be used to get the client's IP address. If you're not using a reverse proxy, you should set those variables to `false`.

---

`GOIABADA_AUTHSERVER_SET_COOKIE_SECURE` and `GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE`

Flag: `--authserver-set-cookie-secure` and `--adminconsole-set-cookie-secure`

Default: false

Description: This should always be set to `true` in production, when using HTTPS. The only scenario where they should be `false` is when testing locally with HTTP only.

---

`GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS` and `GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS`

Flag: `--authserver-log-http-requests` and `--adminconsole-log-http-requests`

Default: false

Description: If `true`, log the HTTP requests to console.

---

`GOIABADA_AUTHSERVER_CERTFILE` and `GOIABADA_ADMINCONSOLE_CERTFILE`

Flag: `--authserver-certfile` and `--adminconsole-certfile`

Default: (empty string)

Description: Certificate file for HTTPS. If empty, TLS will not be enabled.

---

`GOIABADA_AUTHSERVER_KEYFILE` and `GOIABADA_ADMINCONSOLE_KEYFILE`

Flag: `--authserver-keyfile` and `--adminconsole-keyfile`

Default: (empty string)

Description: key file for HTTPS. If empty, TLS will not be enabled.

---

`GOIABADA_AUTHSERVER_LOG_SQL` and `GOIABADA_ADMINCONSOLE_LOG_SQL`

Flag: `--authserver-log-sql` and `--adminconsole-log-sql`

Default: false

Description: If `true`, log all SQL statements to console.

---

`GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE` and `GOIABADA_ADMINCONSOLE_AUDIT_LOGS_IN_CONSOLE`

Flag: `--authserver-audit-logs-in-console` and `--adminconsole-audit-logs-in-console`

Default: false

Description: If `true`, log audit messages to console.

---

`GOIABADA_AUTHSERVER_STATICDIR` and `GOIABADA_ADMINCONSOLE_STATICDIR`

Flag: `--authserver-staticdir` and `--adminconsole-staticdir`

Default: (empty string)

Description: The directory where the static files are located. If empty, it uses the static files embedded into the binary. This config is useful when you want to make modifications to the static files and serve them from the filesystem (perhaps via a docker volume, when running in a container).

---

`GOIABADA_AUTHSERVER_TEMPLATEDIR` and `GOIABADA_ADMINCONSOLE_TEMPLATEDIR`

Flag: `--authserver-templatedir` and `--adminconsole-templatedir`

Default: (empty string)

Description: The directory where the HTML templates are located. If empty, it uses the HTML templates embedded into the binary. This config is useful when you want to make modifications to the templates and serve them from the filesystem (perhaps via a docker volume, when running in a container).

---

`GOIABADA_DB_TYPE`

Flag: `--db-type`

Default: sqlite

Description: Currently `mysql`, `postgres`, `mssql`, `sqlite` are supported.

---

`GOIABADA_DB_USERNAME`

Flag: `--db-username`

Default: root

Description: DB user's name.

---

`GOIABADA_DB_PASSWORD`

Flag: `--db-password`

Default: (empty string)

Description: DB user's password.

---

`GOIABADA_DB_HOST`

Flag: `--db-host`

Default: localhost

Description: DB server hostname.

---

`GOIABADA_DB_PORT`

Flag: `--db-port`

Default: 3306

Description: DB server TCP port.

---

`GOIABADA_DB_NAME`

Flag: `--db-name`

Default: goiabada

Description: Database (schema) name.

---

`GOIABADA_DB_DSN`

Flag: `--db-dsn`

Default: file::memory:?cache=shared

Description: DSN of the database. Only applicable when db type is `sqlite`. When using a file, don't forget to add `?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL`. 

Example: `file:/home/john/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL`

---

`GOIABADA_ADMIN_EMAIL`

Flag: `--admin-email`

Default: admin

Description: The email address of the admin user (the first user created). This is only relevant when the application is started for the first time.

---

`GOIABADA_ADMIN_PASSWORD`

Flag: `--admin-password`

Default: changeme

Description: The password of the admin user (the first user created). This is only relevant when the application is started for the first time.

---

`GOIABADA_APPNAME`

Flag: `--appname`

Default: Goiabada

Description: The name of the application. This is used in the UI and is only relevant when the application is started for the first time (it can be changed in the `adminconsole` later).

---
