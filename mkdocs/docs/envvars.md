# Environment variables

Goiabada uses environment variables to configure the application. 

The following table lists the environment variables and their default values:

####General settings
| <div style="width:190px">Name</div> | Description | <div style="width:150px">Default value</div> |
|:-----|:----------|:----------------|
| `GOIABADA_APPNAME` | The name of the application | `Goiabada` |
| `GOIABADA_ADMIN_EMAIL` | The email address of the admin user (the first user created) | `admin@example.com` |
| `GOIABADA_ADMIN_PASSWORD` | The password of the admin user (the first user created) | `changeme` |

####HTTP listener settings
| <div style="width:300px">Name</div> | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_KEYFILE` | PKCS8 key file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_CERTFILE` | Certificate file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_HOST` | Server's hostname.<br/> The empty string will make it listen on all network interfaces. | `localhost` if not in a container, or empty string if in a container. |
| `GOIABADA_PORT` | Server's TCP port.<br/>If empty and TLS enabled: `8443`, otherwise `8080`. | `8080` (http) or `8443` (https) |
| `GOIABADA_BASEURL` | Server's external URL.<br/>If empty, calculated from TLS enabled state, `GOIABADA_HOST` and `GOIABADA_PORT` | `http://localhost:8080` |
| `GOIABADA_ISSUER` | Value of `iss` field in the generated JWT tokens.<br/>If empty, equals to the `GOIABADA_BASEURL` | `http://localhost:8080` |
| `GOIABADA_STATICDIR` | The directory where the static files are located.<br/>If empty, uses the static files embedded into the binary. | empty |
| `GOIABADA_TEMPLATEDIR` | The directory where the HTML templates are located.<br/>If empty, uses the HTML templates embedded into the binary. | empty |
| `GOIABADA_ISBEHINDAREVERSEPROXY` | If you want to use a reverse proxy in front of Goiabada, set this to `true` | `false` |
| `GOIABADA_RATELIMITER_ENABLED` | An HTTP rate limiter is available to prevent brute force attacks. It's enabled by default. <br/>Some users prefer to apply an HTTP rate limiter from an external service like Cloudflare. If that's you, set this to `false`. | `true` |
| `GOIABADA_RATELIMITER_MAXREQUESTS` | The maximum number of requests allowed per time window.<br />Only relevant if the http rate limiter is enabled. | `50` |
| `GOIABADA_RATELIMITER_WINDOWSIZEINSECONDS` | The rate limiter window size in seconds.<br />Only relevant if the http rate limiter is enabled. | `10` |

####Database settings

| <div style="width:190px">Name</div> | Description | <div style="width:220px">Deafult value</div> |
|:-----|:----------|:----------------|
| `GOIABADA_DB_TYPE` | Currently `mysql` and `sqlite` are supported.<br/>For backward compatibility, the default value is `mysql`, but if `GOIABADA_DB_HOST` isn't defined, then the default is `sqlite`. | `mysql` |
| `GOIABADA_DB_HOST` | DB server hostname. | `localhost` |
| `GOIABADA_DB_PORT` | DB server TCP port. | `3306` |
| `GOIABADA_DB_USERNAME` | DB user's name. | `root` |
| `GOIABADA_DB_PASSWORD` | DB user's password. | empty |
| `GOIABADA_DB_DBNAME` | Database (schema) name. | `goiabada` |
| `GOIABADA_DB_DSN` | DSN of the database. Only applicable when db type is `sqlite`.<br /><br />When using a file, don't forget to add `?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL` (see example on the right).  | `file::memory:?cache=shared`<br /><br />or<br /><br />`file:/home/john/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL` |

####Log settings
| <div style="width:320px">Name</div> | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED` | If `true`, log the HTTP requests. | `false` |
| `GOIABADA_AUDITING_CONSOLELOG_ENABLED` | If `true`, log audit messages to console. | `false` |
| `GOIABADA_LOGGER_GORM_TRACEALL` | If `true`, log all SQL statements to console. | `false` |

When starting Goiabada without any environment variable set, it will listen on `http://localhost:8080` and will use an in-memory SQLite database. 

The admin email and password will be `admin@example.com` and `changeme`. All changes will be lost upon restart. If you want a permanent test environment, specify the `GOIABADA_DB_DSN` = `file:./goiabada.db` environment variable.