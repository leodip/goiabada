package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
)

type ServerConfig struct {
	BaseURL            string
	InternalBaseURL    string
	ListenHostHttps    string
	ListenPortHttps    int
	ListenHostHttp     string
	ListenPortHttp     int
	TrustProxyHeaders  bool
	SetCookieSecure    bool
	LogHttpRequests    bool
	CertFile           string
	KeyFile            string
	LogSQL             bool
	AuditLogsInConsole bool
	StaticDir          string
	TemplateDir        string
}

type DatabaseConfig struct {
	Type     string
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	DSN      string
}

type Config struct {
	AuthServer    ServerConfig
	AdminConsole  ServerConfig
	Database      DatabaseConfig
	AdminEmail    string
	AdminPassword string
	AppName       string
}

var (
	cfg          Config
	activeConfig *ServerConfig
	once         sync.Once
)

// Init initializes the configuration and sets the active server
func Init(server string) {
	once.Do(load)
	setActiveServer(server)
}

// setActiveServer sets the active server configuration
func setActiveServer(server string) {
	switch server {
	case "AuthServer":
		activeConfig = &cfg.AuthServer
	case "AdminConsole":
		activeConfig = &cfg.AdminConsole
	default:
		panic("Invalid active server configuration specified")
	}
}

func Get() *ServerConfig {
	return activeConfig
}

func GetAuthServer() *ServerConfig {
	return &cfg.AuthServer
}

func GetAdminConsole() *ServerConfig {
	return &cfg.AdminConsole
}

func GetDatabase() *DatabaseConfig {
	return &cfg.Database
}

func GetAdminEmail() string {
	return cfg.AdminEmail
}

func GetAdminPassword() string {
	return cfg.AdminPassword
}

func GetAppName() string {
	return cfg.AppName
}

func load() {
	cfg = Config{
		AuthServer: ServerConfig{
			BaseURL:            getEnv("GOIABADA_AUTHSERVER_BASEURL", "http://localhost:9090"),
			InternalBaseURL:    getEnv("GOIABADA_AUTHSERVER_INTERNALBASEURL", ""),
			ListenHostHttps:    getEnv("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS", "0.0.0.0"),
			ListenPortHttps:    getEnvAsInt("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS", 9443),
			ListenHostHttp:     getEnv("GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP", "0.0.0.0"),
			ListenPortHttp:     getEnvAsInt("GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", 9090),
			TrustProxyHeaders:  getEnvAsBool("GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS"),
			SetCookieSecure:    getEnvAsBool("GOIABADA_AUTHSERVER_SET_COOKIE_SECURE"),
			LogHttpRequests:    getEnvAsBool("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS"),
			CertFile:           getEnv("GOIABADA_AUTHSERVER_CERTFILE", ""),
			KeyFile:            getEnv("GOIABADA_AUTHSERVER_KEYFILE", ""),
			LogSQL:             getEnvAsBool("GOIABADA_AUTHSERVER_LOG_SQL"),
			AuditLogsInConsole: getEnvAsBool("GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE"),
			StaticDir:          getEnv("GOIABADA_AUTHSERVER_STATICDIR", ""),
			TemplateDir:        getEnv("GOIABADA_AUTHSERVER_TEMPLATEDIR", ""),
		},
		AdminConsole: ServerConfig{
			BaseURL:            getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:9091"),
			InternalBaseURL:    getEnv("GOIABADA_ADMINCONSOLE_INTERNALBASEURL", ""),
			ListenHostHttps:    getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS", "0.0.0.0"),
			ListenPortHttps:    getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS", 9444),
			ListenHostHttp:     getEnv("GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP", "0.0.0.0"),
			ListenPortHttp:     getEnvAsInt("GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", 9091),
			TrustProxyHeaders:  getEnvAsBool("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS"),
			SetCookieSecure:    getEnvAsBool("GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE"),
			LogHttpRequests:    getEnvAsBool("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS"),
			CertFile:           getEnv("GOIABADA_ADMINCONSOLE_CERTFILE", ""),
			KeyFile:            getEnv("GOIABADA_ADMINCONSOLE_KEYFILE", ""),
			LogSQL:             getEnvAsBool("GOIABADA_ADMINCONSOLE_LOG_SQL"),
			AuditLogsInConsole: getEnvAsBool("GOIABADA_ADMINCONSOLE_AUDIT_LOGS_IN_CONSOLE"),
			StaticDir:          getEnv("GOIABADA_ADMINCONSOLE_STATICDIR", ""),
			TemplateDir:        getEnv("GOIABADA_ADMINCONSOLE_TEMPLATEDIR", ""),
		},
		Database: DatabaseConfig{
			Type:     getEnv("GOIABADA_DB_TYPE", "sqlite"),
			Username: getEnv("GOIABADA_DB_USERNAME", "root"),
			Password: getEnv("GOIABADA_DB_PASSWORD", ""),
			Host:     getEnv("GOIABADA_DB_HOST", "localhost"),
			Port:     getEnvAsInt("GOIABADA_DB_PORT", 3306),
			Name:     getEnv("GOIABADA_DB_NAME", "goiabada"),
			DSN:      getEnv("GOIABADA_DB_DSN", "file::memory:?cache=shared"),
		},
		AdminEmail:    getEnv("GOIABADA_AUTHSERVER_ADMIN_EMAIL", "admin"),
		AdminPassword: getEnv("GOIABADA_AUTHSERVER_ADMIN_PASSWORD", "admin"),
		AppName:       getEnv("GOIABADA_AUTHSERVER_APPNAME", "app"),
	}

	// Auth server
	flag.StringVar(&cfg.AuthServer.BaseURL, "authserver-baseurl", cfg.AuthServer.BaseURL, "Goiabada auth server base URL")
	flag.StringVar(&cfg.AuthServer.InternalBaseURL, "authserver-internalbaseurl", cfg.AuthServer.InternalBaseURL, "Goiabada auth server internal base URL")
	flag.StringVar(&cfg.AuthServer.ListenHostHttps, "authserver-listen-https-host", cfg.AuthServer.ListenHostHttps, "Auth server https host")
	flag.IntVar(&cfg.AuthServer.ListenPortHttps, "authserver-listen-https-port", cfg.AuthServer.ListenPortHttps, "Auth server https port")
	flag.StringVar(&cfg.AuthServer.ListenHostHttp, "authserver-listen-http-host", cfg.AuthServer.ListenHostHttp, "Auth server http host")
	flag.IntVar(&cfg.AuthServer.ListenPortHttp, "authserver-listen-http-port", cfg.AuthServer.ListenPortHttp, "Auth server http port")
	flag.BoolVar(&cfg.AuthServer.TrustProxyHeaders, "authserver-trust-proxy-headers", cfg.AuthServer.TrustProxyHeaders, "Trust HTTP headers from reverse proxy in Auth server? (True-Client-IP, X-Real-IP or the X-Forwarded-For headers)")
	flag.BoolVar(&cfg.AuthServer.SetCookieSecure, "authserver-set-cookie-secure", cfg.AuthServer.SetCookieSecure, "Set secure flag on cookies for auth server")
	flag.BoolVar(&cfg.AuthServer.LogHttpRequests, "authserver-log-http-requests", cfg.AuthServer.LogHttpRequests, "Log HTTP requests for auth server")
	flag.StringVar(&cfg.AuthServer.CertFile, "authserver-certfile", cfg.AuthServer.CertFile, "Certificate file for HTTPS (auth server)")
	flag.StringVar(&cfg.AuthServer.KeyFile, "authserver-keyfile", cfg.AuthServer.KeyFile, "Key file for HTTPS (auth server)")
	flag.BoolVar(&cfg.AuthServer.LogSQL, "authserver-log-sql", cfg.AuthServer.LogSQL, "Log SQL queries for auth server")
	flag.BoolVar(&cfg.AuthServer.AuditLogsInConsole, "authserver-audit-logs-in-console", cfg.AuthServer.AuditLogsInConsole, "Enable audit logs in console output for auth server")
	flag.StringVar(&cfg.AuthServer.StaticDir, "authserver-staticdir", cfg.AuthServer.StaticDir, "Static files directory for auth server")
	flag.StringVar(&cfg.AuthServer.TemplateDir, "authserver-templatedir", cfg.AuthServer.TemplateDir, "Template files directory for auth server")

	// Admin console
	flag.StringVar(&cfg.AdminConsole.BaseURL, "adminconsole-baseurl", cfg.AdminConsole.BaseURL, "Goiabada admin console base URL")
	flag.StringVar(&cfg.AdminConsole.InternalBaseURL, "adminconsole-internalbaseurl", cfg.AdminConsole.InternalBaseURL, "Goiabada admin console internal base URL")
	flag.StringVar(&cfg.AdminConsole.ListenHostHttps, "adminconsole-listen-https-host", cfg.AdminConsole.ListenHostHttps, "Admin console https host")
	flag.IntVar(&cfg.AdminConsole.ListenPortHttps, "adminconsole-listen-https-port", cfg.AdminConsole.ListenPortHttps, "Admin console https port")
	flag.StringVar(&cfg.AdminConsole.ListenHostHttp, "adminconsole-listen-http-host", cfg.AdminConsole.ListenHostHttp, "Admin console http host")
	flag.IntVar(&cfg.AdminConsole.ListenPortHttp, "adminconsole-listen-http-port", cfg.AdminConsole.ListenPortHttp, "Admin console http port")
	flag.BoolVar(&cfg.AdminConsole.TrustProxyHeaders, "adminconsole-trust-proxy-headers", cfg.AdminConsole.TrustProxyHeaders, "Trust HTTP headers from reverse proxy in Admin console? (True-Client-IP, X-Real-IP or the X-Forwarded-For headers)")
	flag.BoolVar(&cfg.AdminConsole.SetCookieSecure, "adminconsole-set-cookie-secure", cfg.AdminConsole.SetCookieSecure, "Set secure flag on cookies for admin console")
	flag.BoolVar(&cfg.AdminConsole.LogHttpRequests, "adminconsole-log-http-requests", cfg.AdminConsole.LogHttpRequests, "Log HTTP requests for admin console")
	flag.StringVar(&cfg.AdminConsole.CertFile, "adminconsole-certfile", cfg.AdminConsole.CertFile, "Certificate file for HTTPS (admin console)")
	flag.StringVar(&cfg.AdminConsole.KeyFile, "adminconsole-keyfile", cfg.AdminConsole.KeyFile, "Key file for HTTPS (admin console)")
	flag.BoolVar(&cfg.AdminConsole.LogSQL, "adminconsole-log-sql", cfg.AdminConsole.LogSQL, "Log SQL queries for admin console")
	flag.BoolVar(&cfg.AdminConsole.AuditLogsInConsole, "adminconsole-audit-logs-in-console", cfg.AdminConsole.AuditLogsInConsole, "Enable audit logs in console output for admin console")
	flag.StringVar(&cfg.AdminConsole.StaticDir, "adminconsole-staticdir", cfg.AdminConsole.StaticDir, "Static files directory for admin console")
	flag.StringVar(&cfg.AdminConsole.TemplateDir, "adminconsole-templatedir", cfg.AdminConsole.TemplateDir, "Template files directory for admin console")

	// Database
	flag.StringVar(&cfg.Database.Type, "db-type", cfg.Database.Type, "Database type. Options: mysql, sqlite")
	flag.StringVar(&cfg.Database.Username, "db-username", cfg.Database.Username, "Database username")
	flag.StringVar(&cfg.Database.Password, "db-password", cfg.Database.Password, "Database password")
	flag.StringVar(&cfg.Database.Host, "db-host", cfg.Database.Host, "Database host")
	flag.IntVar(&cfg.Database.Port, "db-port", cfg.Database.Port, "Database port")
	flag.StringVar(&cfg.Database.Name, "db-name", cfg.Database.Name, "Database name")
	flag.StringVar(&cfg.Database.DSN, "db-dsn", cfg.Database.DSN, "Database DSN (only for sqlite)")

	// Initial setup
	flag.StringVar(&cfg.AdminEmail, "admin-email", cfg.AdminEmail, "Default admin email")
	flag.StringVar(&cfg.AdminPassword, "admin-password", cfg.AdminPassword, "Default admin password")
	flag.StringVar(&cfg.AppName, "appname", cfg.AppName, "Default app name")

	flag.Parse()
}

func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(defaultVal)
}

func getEnvAsInt(key string, defaultVal int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(strings.TrimSpace(valueStr)); err == nil {
		return value
	}
	return defaultVal
}

func getEnvAsBool(key string) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(strings.TrimSpace(valueStr)); err == nil {
		return value
	}
	return false
}
