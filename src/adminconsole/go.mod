module github.com/leodip/goiabada/adminconsole

go 1.27.1

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/leodip/goiabada/core v0.0.0
	github.com/stretchr/testify v1.12.1
)

replace github.com/leodip/goiabada/core => ../core

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
