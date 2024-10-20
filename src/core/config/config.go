package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
)

type ServerConfig struct {
	BaseURL               string
	Host                  string
	Port                  string
	IsBehindAReverseProxy bool
	LogHttpRequests       bool
	RateLimiter           struct {
		Enabled             bool
		MaxRequests         int
		WindowSizeInSeconds int
	}
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
			BaseURL:               getEnv("GOIABADA_AUTHSERVER_BASEURL", "http://localhost:8080"),
			Host:                  getEnv("GOIABADA_AUTHSERVER_HOST", "0.0.0.0"),
			Port:                  getEnv("GOIABADA_AUTHSERVER_PORT", "8080"),
			IsBehindAReverseProxy: getEnvAsBool("GOIABADA_AUTHSERVER_ISBEHINDAREVERSEPROXY"),
			LogHttpRequests:       getEnvAsBool("GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS"),
			RateLimiter: struct {
				Enabled             bool
				MaxRequests         int
				WindowSizeInSeconds int
			}{
				Enabled:             getEnvAsBool("GOIABADA_AUTHSERVER_RATELIMITER_ENABLED"),
				MaxRequests:         getEnvAsInt("GOIABADA_AUTHSERVER_RATELIMITER_MAXREQUESTS", 50),
				WindowSizeInSeconds: getEnvAsInt("GOIABADA_AUTHSERVER_RATELIMITER_WINDOWSIZEINSECONDS", 10),
			},
			CertFile:           getEnv("GOIABADA_AUTHSERVER_CERTFILE", ""),
			KeyFile:            getEnv("GOIABADA_AUTHSERVER_KEYFILE", ""),
			LogSQL:             getEnvAsBool("GOIABADA_AUTHSERVER_LOG_SQL"),
			AuditLogsInConsole: getEnvAsBool("GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE"),
			StaticDir:          getEnv("GOIABADA_AUTHSERVER_STATICDIR", ""),
			TemplateDir:        getEnv("GOIABADA_AUTHSERVER_TEMPLATEDIR", ""),
		},
		AdminConsole: ServerConfig{
			BaseURL:               getEnv("GOIABADA_ADMINCONSOLE_BASEURL", "http://localhost:8081"),
			Host:                  getEnv("GOIABADA_ADMINCONSOLE_HOST", "0.0.0.0"),
			Port:                  getEnv("GOIABADA_ADMINCONSOLE_PORT", "8081"),
			IsBehindAReverseProxy: getEnvAsBool("GOIABADA_ADMINCONSOLE_ISBEHINDAREVERSEPROXY"),
			LogHttpRequests:       getEnvAsBool("GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS"),
			RateLimiter: struct {
				Enabled             bool
				MaxRequests         int
				WindowSizeInSeconds int
			}{
				Enabled:             getEnvAsBool("GOIABADA_ADMINCONSOLE_RATELIMITER_ENABLED"),
				MaxRequests:         getEnvAsInt("GOIABADA_ADMINCONSOLE_RATELIMITER_MAXREQUESTS", 50),
				WindowSizeInSeconds: getEnvAsInt("GOIABADA_ADMINCONSOLE_RATELIMITER_WINDOWSIZEINSECONDS", 10),
			},
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

	flag.StringVar(&cfg.AuthServer.BaseURL, "authserver-baseurl", cfg.AuthServer.BaseURL, "Goiabada auth server base URL")
	flag.StringVar(&cfg.AuthServer.Host, "authserver-host", cfg.AuthServer.Host, "Auth server host")
	flag.StringVar(&cfg.AuthServer.Port, "authserver-port", cfg.AuthServer.Port, "Auth server port")
	flag.BoolVar(&cfg.AuthServer.IsBehindAReverseProxy, "authserver-is-behind-a-reverse-proxy", cfg.AuthServer.IsBehindAReverseProxy, "Is the auth server behind a reverse proxy?")
	flag.BoolVar(&cfg.AuthServer.LogHttpRequests, "authserver-log-http-requests", cfg.AuthServer.LogHttpRequests, "Log HTTP requests for auth server")
	flag.BoolVar(&cfg.AuthServer.RateLimiter.Enabled, "authserver-ratelimiter-enabled", cfg.AuthServer.RateLimiter.Enabled, "Enable rate limiter for auth server")
	flag.IntVar(&cfg.AuthServer.RateLimiter.MaxRequests, "authserver-ratelimiter-max-requests", cfg.AuthServer.RateLimiter.MaxRequests, "Max requests for auth server rate limiter")
	flag.IntVar(&cfg.AuthServer.RateLimiter.WindowSizeInSeconds, "authserver-ratelimiter-window-size", cfg.AuthServer.RateLimiter.WindowSizeInSeconds, "Window size in seconds for auth server rate limiter")
	flag.StringVar(&cfg.AuthServer.CertFile, "authserver-certfile", cfg.AuthServer.CertFile, "Certificate file for HTTPS (auth server)")
	flag.StringVar(&cfg.AuthServer.KeyFile, "authserver-keyfile", cfg.AuthServer.KeyFile, "Key file for HTTPS (auth server)")
	flag.BoolVar(&cfg.AuthServer.LogSQL, "authserver-log-sql", cfg.AuthServer.LogSQL, "Log SQL queries for auth server")
	flag.BoolVar(&cfg.AuthServer.AuditLogsInConsole, "authserver-audit-logs-in-console", cfg.AuthServer.AuditLogsInConsole, "Enable audit logs in console output for auth server")
	flag.StringVar(&cfg.AuthServer.StaticDir, "authserver-staticdir", cfg.AuthServer.StaticDir, "Static files directory for auth server")
	flag.StringVar(&cfg.AuthServer.TemplateDir, "authserver-templatedir", cfg.AuthServer.TemplateDir, "Template files directory for auth server")

	flag.StringVar(&cfg.AdminConsole.BaseURL, "adminconsole-baseurl", cfg.AdminConsole.BaseURL, "Goiabada admin console base URL")
	flag.StringVar(&cfg.AdminConsole.Host, "adminconsole-host", cfg.AdminConsole.Host, "Admin console host")
	flag.StringVar(&cfg.AdminConsole.Port, "adminconsole-port", cfg.AdminConsole.Port, "Admin console port")
	flag.BoolVar(&cfg.AdminConsole.IsBehindAReverseProxy, "adminconsole-is-behind-a-reverse-proxy", cfg.AdminConsole.IsBehindAReverseProxy, "Is the admin console behind a reverse proxy?")
	flag.BoolVar(&cfg.AdminConsole.LogHttpRequests, "adminconsole-log-http-requests", cfg.AdminConsole.LogHttpRequests, "Log HTTP requests for admin console")
	flag.BoolVar(&cfg.AdminConsole.RateLimiter.Enabled, "adminconsole-ratelimiter-enabled", cfg.AdminConsole.RateLimiter.Enabled, "Enable rate limiter for admin console")
	flag.IntVar(&cfg.AdminConsole.RateLimiter.MaxRequests, "adminconsole-ratelimiter-max-requests", cfg.AdminConsole.RateLimiter.MaxRequests, "Max requests for admin console rate limiter")
	flag.IntVar(&cfg.AdminConsole.RateLimiter.WindowSizeInSeconds, "adminconsole-ratelimiter-window-size", cfg.AdminConsole.RateLimiter.WindowSizeInSeconds, "Window size in seconds for admin console rate limiter")
	flag.StringVar(&cfg.AdminConsole.CertFile, "adminconsole-certfile", cfg.AdminConsole.CertFile, "Certificate file for HTTPS (admin console)")
	flag.StringVar(&cfg.AdminConsole.KeyFile, "adminconsole-keyfile", cfg.AdminConsole.KeyFile, "Key file for HTTPS (admin console)")
	flag.BoolVar(&cfg.AdminConsole.LogSQL, "adminconsole-log-sql", cfg.AdminConsole.LogSQL, "Log SQL queries for admin console")
	flag.BoolVar(&cfg.AdminConsole.AuditLogsInConsole, "adminconsole-audit-logs-in-console", cfg.AdminConsole.AuditLogsInConsole, "Enable audit logs in console output for admin console")
	flag.StringVar(&cfg.AdminConsole.StaticDir, "adminconsole-staticdir", cfg.AdminConsole.StaticDir, "Static files directory for admin console")
	flag.StringVar(&cfg.AdminConsole.TemplateDir, "adminconsole-templatedir", cfg.AdminConsole.TemplateDir, "Template files directory for admin console")

	flag.StringVar(&cfg.Database.Type, "db-type", cfg.Database.Type, "Database type. Options: mysql, sqlite")
	flag.StringVar(&cfg.Database.Username, "db-username", cfg.Database.Username, "Database username")
	flag.StringVar(&cfg.Database.Password, "db-password", cfg.Database.Password, "Database password")
	flag.StringVar(&cfg.Database.Host, "db-host", cfg.Database.Host, "Database host")
	flag.IntVar(&cfg.Database.Port, "db-port", cfg.Database.Port, "Database port")
	flag.StringVar(&cfg.Database.Name, "db-name", cfg.Database.Name, "Database name")
	flag.StringVar(&cfg.Database.DSN, "db-dsn", cfg.Database.DSN, "Database DSN (only for sqlite)")

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

func (s *ServerConfig) IsHttpsEnabled() bool {
	return strings.TrimSpace(s.CertFile) != "" && strings.TrimSpace(s.KeyFile) != ""
}
