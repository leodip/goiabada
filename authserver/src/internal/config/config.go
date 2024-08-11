package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	AuthServerBaseUrl              string
	AdminConsoleBaseUrl            string
	AdminEmail                     string
	AdminPassword                  string
	AppName                        string
	Host                           string
	Port                           string
	IsBehindAReverseProxy          bool
	LogHttpRequests                bool
	RateLimiterEnabled             bool
	RateLimiterMaxRequests         int
	RateLimiterWindowSizeInSeconds int
	DBType                         string
	DBUsername                     string
	DBPassword                     string
	DBHost                         string
	DBPort                         int
	DBName                         string
	DBDSN                          string
	CertFile                       string
	KeyFile                        string
	LogSql                         bool
	AuditLogsInConsole             bool
	StaticDir                      string
	TemplateDir                    string
	once                           sync.Once
)

func Init() {
	once.Do(load)
}

func load() {

	AuthServerBaseUrl = getEnv("GOIABADA_AUTHSERVER_BASEURL", "http://localhost:8080")
	AdminConsoleBaseUrl = getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:8081")
	AdminEmail = getEnv("GOIABADA_AUTHSERVER_ADMIN_EMAIL", "admin")
	AdminPassword = getEnv("GOIABADA_AUTHSERVER_ADMIN_PASSWORD", "admin")
	AppName = getEnv("GOIABADA_AUTHSERVER_APPNAME", "app")
	Host = getEnv("GOIABADA_AUTHSERVER_HOST", "0.0.0.0")
	Port = getEnv("GOIABADA_AUTHSERVER_PORT", "8080")
	IsBehindAReverseProxy = getEnvAsBool("GOIABADA_AUTHSERVER_ISBEHINDAREVERSEPROXY")
	LogHttpRequests = getEnvAsBool("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS")
	RateLimiterEnabled = getEnvAsBool("GOIABADA_AUTHSERVER_RATELIMITER_ENABLED")
	RateLimiterMaxRequests = getEnvAsInt("GOIABADA_AUTHSERVER_RATELIMITER_MAXREQUESTS", 50)
	RateLimiterWindowSizeInSeconds = getEnvAsInt("GOIABADA_AUTHSERVER_RATELIMITER_WINDOWSIZEINSECONDS", 10)
	DBType = getEnv("GOIABADA_AUTHSERVER_DB_TYPE", "mysql")
	DBUsername = getEnv("GOIABADA_AUTHSERVER_DB_USERNAME", "root")
	DBPassword = getEnv("GOIABADA_AUTHSERVER_DB_PASSWORD", "")
	DBHost = getEnv("GOIABADA_AUTHSERVER_DB_HOST", "localhost")
	DBPort = getEnvAsInt("GOIABADA_AUTHSERVER_DB_PORT", 3306)
	DBName = getEnv("GOIABADA_AUTHSERVER_DB_NAME", "goiabada")
	DBDSN = getEnv("GOIABADA_AUTHSERVER_DB_DSN", "file::memory:?cache=shared")
	CertFile = getEnv("GOIABADA_AUTHSERVER_CERTFILE", "")
	KeyFile = getEnv("GOIABADA_AUTHSERVER_KEYFILE", "")
	LogSql = getEnvAsBool("GOIABADA_AUTHSERVER_LOG_SQL")
	AuditLogsInConsole = getEnvAsBool("GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE")
	StaticDir = getEnv("GOIABADA_AUTHSERVER_STATICDIR", "")
	TemplateDir = getEnv("GOIABADA_AUTHSERVER_TEMPLATEDIR", "")

	flag.StringVar(&AuthServerBaseUrl, "authserver-baseurl", AuthServerBaseUrl, "Goiabada auth server base URL. Default: http://localhost:8080")
	flag.StringVar(&AdminConsoleBaseUrl, "adminconsole-baseurl", AdminConsoleBaseUrl, "Goiabada admin console base URL. Default: http://localhost:8081")
	flag.StringVar(&AdminEmail, "admin-email", AdminEmail, "Default admin email. Default: admin")
	flag.StringVar(&AdminPassword, "admin-password", AdminPassword, "Default admin password. Default: admin")
	flag.StringVar(&AppName, "appname", AppName, "Default app name. Default: Goiabada")
	flag.StringVar(&Host, "host", Host, "Auth server server host. Default: 0.0.0.0")
	flag.StringVar(&Port, "port", Port, "Auth server port. Default: 8080")
	flag.BoolVar(&IsBehindAReverseProxy, "is-behind-a-reverse-proxy", IsBehindAReverseProxy, "Is the auth server server behind a reverse proxy? Default: false")
	flag.BoolVar(&LogHttpRequests, "log-http-requests", LogHttpRequests, "Log HTTP requests. Default: false")
	flag.BoolVar(&RateLimiterEnabled, "ratelimiter-enabled", RateLimiterEnabled, "Enable rate limiter. Default: false")
	flag.StringVar(&DBType, "db-type", DBType, "Database type. Options: mysql, sqlite. Default: mysql")
	flag.StringVar(&DBUsername, "db-username", DBUsername, "Database username. Default: root")
	flag.StringVar(&DBPassword, "db-password", DBPassword, "Database password. Default: (empty)")
	flag.StringVar(&DBHost, "db-host", DBHost, "Database host. Default: localhost")
	flag.IntVar(&DBPort, "db-port", DBPort, "Database port. Default: 3306")
	flag.StringVar(&DBName, "db-name", DBName, "Database name. Default: goiabada")
	flag.StringVar(&DBDSN, "db-dsn", DBDSN, "Database DSN (only for sqlite). Default: file::memory:?cache=shared")
	flag.StringVar(&CertFile, "certfile", CertFile, "Certificate file for HTTPS. Default: (empty)")
	flag.StringVar(&KeyFile, "keyfile", KeyFile, "Key file for HTTPS. Default: (empty)")
	flag.BoolVar(&LogSql, "log-sql", LogSql, "Log SQL queries. Default: false")
	flag.BoolVar(&AuditLogsInConsole, "audit-logs-in-console", AuditLogsInConsole, "Enable audit logs in console output. Default: false")
	flag.StringVar(&StaticDir, "staticdir", StaticDir, "Static files directory. Default: (empty)")
	flag.StringVar(&TemplateDir, "templatedir", TemplateDir, "Template files directory. Default: (empty)")

	flag.Parse()
}

func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultVal
}

func getEnvAsBool(key string) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return false
}

func IsHttpsEnabled() bool {
	httpsEnabled := true

	if strings.TrimSpace(CertFile) == "" || strings.TrimSpace(KeyFile) == "" {
		httpsEnabled = false
	}

	return httpsEnabled
}
