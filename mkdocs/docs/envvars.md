# Environment variables

Goiabada uses environment variables to configure the application. 

The following table lists the environment variables and their default values:

| Name | Description | Default value |
|:-----|:----------|:----------------|
| `GOIABADA_APPNAME` | The name of the application | `Goiabada` |
| `GOIABADA_ADMIN_EMAIL` | The email address of the admin user (the first user created) | `admin@example.com` |
| `GOIABADA_ADMIN_EMAIL` | The password of the admin user (the first user created) | `admin123` |
| ***<div style="text-align: center;">HTTP listener settings</div>*** |
| `GOIABADA_KEYFILE` | PKCS8 key file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_CERTFILE` | Certificate file for https.<br/>If empty, TLS will not be enabled. | empty |
| `GOIABADA_HOST` | Server's hostname. | `localhost` |
| `GOIABADA_PORT` | Server's TCP port.<br/>If empty and TLS enabled: `8443`, otherwise `8080`. | `8080` |
| `GOIABADA_BASEURL` | Server's external URL.<br/>If empty, calculated from TLS enabled state, `GOIABADA_HOST` and `GOIABADA_PORT` | `http://localhost:8080` |
| `GOIABADA_ISSUER` | Value of `iss` field in the generated JWT tokens.<br/>If empty, equals to the `GOIABADA_BASEURL` | `http://localhost:8080` |
| `GOIABADA_STATICDIR` | The directory where the static files are located.<br/>If empty, uses the static files embedded into the binary. | empty |
| `GOIABADA_TEMPLATEDIR` | The directory where the HTML templates are located.<br/>If empty, uses the HTML templates embedded into the binary. | empty |
| `GOIABADA_ISBEHINDAREVERSEPROXY` | If you want to use a reverse proxy in front of Goiabada, set this to `true` | `false` |
| ***<div style="text-align: center;">Database settings</div>*** |
| `GOIABADA_DB_TYPE` | Currently `mysql` and `sqlite` are supported. For backward compatibility, the default value is `mysql`, but if `GOIABADA_DB_HOST` isn't defined, then the default is `sqlite`. | `mysql` |
| `GOIABADA_DB_HOST` | DB server hostname. | `localhost` |
| `GOIABADA_DB_PORT` | DB server TCP port. | `3306` |
| `GOIABADA_DB_USERNAME` | DB user's name. | `root` |
| `GOIABADA_DB_PASSWORD` | DB user's password. | empty |
| `GOIABADA_DB_DBNAME` | Database (schema) name. | `goiabada` |
| `GOIABADA_DB_DSN` | DSN of the databes. Used when db type is `sqlite`. | `file::memory:?cache=shared` |
| ***<div style="text-align: center;">Log settings</div>*** |
| `GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED` | If `true`, log the HTTP requests. | `false` |
| `GOIABADA_AUDITING_CONSOLELOG_ENABLED` | If `true`, log audit messages to console. | `false` |
| `GOIABADA_LOGGER_GORM_TRACEALL` | If `true`, log all SQL statement to console. | `false` |

Starting without any environment variable Goiabada will listen on http://localhost:8080 and uses an in-memory SQLite database. The initial user's name and password will be `admin@example.com` and `admin123`. All changes will be lost upon restart. If you want a permanent test environment, specify the `GOIABADA_DB_DSN` = `file:./goiabada.db` environment variable. 
 

