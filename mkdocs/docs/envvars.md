# Environment variables

Goiabada uses environment variables to configure the application. 

The following table lists the environment variables and their default values:

####General settings
| Name | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_APPNAME` | The name of the application | `Goiabada` |
| `GOIABADA_ADMIN_EMAIL` | The email address of the admin user (the first user created) | `admin@example.com` |
| `GOIABADA_ADMIN_PASSWORD` | The password of the admin user (the first user created) | `changeme` |

####HTTP listener settings
| Name | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_KEYFILE` | PKCS8 key file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_CERTFILE` | Certificate file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_HOST` | Server's hostname. | `localhost` if outside of a container, or empty string if running inside a container. The empty string will make it listen on all network interfaces |
| `GOIABADA_PORT` | Server's TCP port.<br/>If empty and TLS enabled: `8443`, otherwise `8080`. | `8080` (http) or `8443` (https) |
| `GOIABADA_BASEURL` | Server's external URL.<br/>If empty, calculated from TLS enabled state, `GOIABADA_HOST` and `GOIABADA_PORT` | `http://localhost:8080` |
| `GOIABADA_ISSUER` | Value of `iss` field in the generated JWT tokens.<br/>If empty, equals to the `GOIABADA_BASEURL` | `http://localhost:8080` |
| `GOIABADA_STATICDIR` | The directory where the static files are located.<br/>If empty, uses the static files embedded into the binary. | empty |
| `GOIABADA_TEMPLATEDIR` | The directory where the HTML templates are located.<br/>If empty, uses the HTML templates embedded into the binary. | empty |
| `GOIABADA_ISBEHINDAREVERSEPROXY` | If you want to use a reverse proxy in front of Goiabada, set this to `true` | `false` |

####Database settings
| Name | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_DB_TYPE` | Currently `mysql` and `sqlite` are supported. For backward compatibility, the default value is `mysql`, but if `GOIABADA_DB_HOST` isn't defined, then the default is `sqlite`. | `mysql` |
| `GOIABADA_DB_HOST` | DB server hostname. | `localhost` |
| `GOIABADA_DB_PORT` | DB server TCP port. | `3306` |
| `GOIABADA_DB_USERNAME` | DB user's name. | `root` |
| `GOIABADA_DB_PASSWORD` | DB user's password. | empty |
| `GOIABADA_DB_DBNAME` | Database (schema) name. | `goiabada` |
| `GOIABADA_DB_DSN` | DSN of the database. Only applicable when db type is `sqlite`. | `file::memory:?cache=shared` |

####Log settings
| Name | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED` | If `true`, log the HTTP requests. | `false` |
| `GOIABADA_AUDITING_CONSOLELOG_ENABLED` | If `true`, log audit messages to console. | `false` |
| `GOIABADA_LOGGER_GORM_TRACEALL` | If `true`, log all SQL statements to console. | `false` |

When starting Goiabada without any environment variable set, it will listen on `http://localhost:8080` and will use an in-memory SQLite database. 

The admin email and password will be `admin@example.com` and `changeme`. All changes will be lost upon restart. If you want a permanent test environment, specify the `GOIABADA_DB_DSN` = `file:./goiabada.db` environment variable.