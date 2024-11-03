# OAuth2/OIDC Test Application

A simple Go web application to test OAuth2/OpenID Connect integration with [Goiabada](https://github.com/goiabada) authentication server.

## Setup

1. Clone the repository
2. Choose one:
   - Use VS Code + Dev Containers to run in a container
   - Run locally with Go 1.23.2+
3. Update auth server settings in `config/config.go`
4. Run: `go run main.go`
5. Visit `http://localhost:3000`

## Features

- OAuth2/OIDC authentication with PKCE
- Protected routes requiring:
  - Authentication only
  - Specific scope only
  - Both authentication and scope
- Token management and session handling
- Configurable OIDC scopes

## Requirements

- Go 1.23.2+ (if running locally)
- Docker and Docker Compose (if using Dev Container)
- Running instance of Goiabada auth server