package main

// testConfig is a fully populated wizard answer set. Every field carries a distinguishable
// value so a generator that emitted the wrong one would still be visible in a failure.
func testConfig() *Config {
	return &Config{
		DeploymentType:      "2",
		DBType:              "postgres",
		DBImage:             "postgres:17",
		DBPort:              "5432",
		DBHost:              "goiabada-db",
		DBName:              "goiabada",
		DBUsername:          "goiabada-user",
		DBPassword:          "db-password",
		AuthServerURL:       "https://auth.example.com",
		AdminConsoleURL:     "https://admin.example.com",
		AdminEmail:          "admin@example.com",
		AdminPassword:       "admin-password",
		AuthSessionAuthKey:  "auth-session-auth-key",
		AuthSessionEncKey:   "auth-session-enc-key",
		AdminSessionAuthKey: "admin-session-auth-key",
		AdminSessionEncKey:  "admin-session-enc-key",
		AESEncryptionKey:    "aes-encryption-key",
		OAuthClientSecret:   "oauth-client-secret",
		K8sNamespace:        "goiabada",
	}
}
