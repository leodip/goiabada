package main

// Config holds all configuration values
type Config struct {
	DeploymentType      string
	DBType              string
	DBImage             string
	DBPort              string
	DBHost              string
	DBName              string
	DBUsername          string
	DBPassword          string
	AuthServerURL       string
	AdminConsoleURL     string
	AdminEmail          string
	AdminPassword       string
	AuthSessionAuthKey  string
	AuthSessionEncKey   string
	AdminSessionAuthKey string
	AdminSessionEncKey  string
	AESEncryptionKey    string
	OAuthClientSecret   string
	K8sNamespace        string
}
